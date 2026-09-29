package ws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/grafana/sobek"
	"go.k6.io/k6/v2/js/common"
	"go.k6.io/k6/v2/js/modules"
	"go.k6.io/k6/v2/lib"

	"github.com/XavierChevalier/xk6-tlsauth/internal/tlsauth"
)

func init() {
	modules.Register("k6/x/tlsauth/ws", New())
}

// RootModule is registered once per test run.
type RootModule struct{}

// ModuleInstance is the per-VU WebSocket extension instance.
type ModuleInstance struct {
	vu modules.VU
}

// ConnectResult is returned from connect.
type ConnectResult struct {
	Status int `json:"status"`
}

// Socket is the JS-facing WebSocket handle.
type Socket struct {
	rt            *sobek.Runtime
	conn          *websocket.Conn
	eventHandlers map[string][]sobek.Callable
	done          chan struct{}
	shutdownOnce  sync.Once
}

type connectParams struct {
	tlsAuth any
	headers http.Header
	tags    map[string]string
}

var (
	_ modules.Module   = &RootModule{}
	_ modules.Instance = &ModuleInstance{}
)

const writeWait = 10 * time.Second

// New returns the root module.
func New() *RootModule {
	return &RootModule{}
}

// NewModuleInstance implements modules.Module.
func (r *RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	return &ModuleInstance{vu: vu}
}

// Exports implements modules.Instance.
func (mi *ModuleInstance) Exports() modules.Exports {
	rt := mi.vu.Runtime()
	obj := rt.NewObject()
	if err := obj.Set("connect", mi.jsConnect); err != nil {
		common.Throw(rt, err)
	}
	return modules.Exports{Default: obj}
}

func (mi *ModuleInstance) jsConnect(call sobek.FunctionCall) sobek.Value {
	url := call.Argument(0).String()
	var params map[string]any
	var setupFn func(*Socket)
	switch len(call.Arguments) {
	case 3:
		if !common.IsNullish(call.Argument(1)) {
			if m, ok := call.Argument(1).Export().(map[string]any); ok {
				params = m
			}
		}
		setupFn = socketSetupFromValue(mi.vu.Runtime(), call.Argument(2))
	case 2:
		setupFn = socketSetupFromValue(mi.vu.Runtime(), call.Argument(1))
	default:
		common.Throw(mi.vu.Runtime(), errors.New("invalid number of arguments to ws.connect"))
		return sobek.Undefined()
	}
	res, err := mi.Connect(url, params, setupFn)
	if err != nil {
		common.Throw(mi.vu.Runtime(), err)
	}
	return mi.vu.Runtime().ToValue(res)
}

func socketSetupFromValue(rt *sobek.Runtime, v sobek.Value) func(*Socket) {
	fn, ok := sobek.AssertFunction(v)
	if !ok {
		common.Throw(rt, errors.New("last argument to ws.connect must be a function"))
		return nil
	}
	return func(socket *Socket) {
		if _, err := fn(sobek.Undefined(), rt.ToValue(socket)); err != nil {
			common.Throw(rt, err)
		}
	}
}

// Connect dials WSS with optional per-request tlsAuth and runs the socket event loop until close.
func (mi *ModuleInstance) Connect(url string, params map[string]any, setupFn func(*Socket)) (*ConnectResult, error) {
	state := mi.vu.State()
	if state == nil {
		return nil, common.NewInitContextError("using websockets in the init context is not supported")
	}

	p, err := parseParams(params, state)
	if err != nil {
		return nil, err
	}

	ctx := mi.vu.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	tlsConfig, err := buildTLSConfig(state, p.tlsAuth)
	if err != nil {
		return nil, err
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 60 * time.Second,
		TLSClientConfig:  tlsConfig,
		Proxy:            http.ProxyFromEnvironment,
	}
	if state.Dialer != nil {
		dialer.NetDialContext = state.Dialer.DialContext
	}

	conn, httpResp, dialErr := dialer.DialContext(ctx, url, p.headers)
	if dialErr != nil {
		if errors.Is(dialErr, websocket.ErrBadHandshake) && httpResp != nil {
			return nil, fmt.Errorf("%w: status %d", dialErr, httpResp.StatusCode)
		}
		return nil, dialErr
	}

	status := 0
	if httpResp != nil {
		status = httpResp.StatusCode
		_ = httpResp.Body.Close()
	}

	rt := mi.vu.Runtime()
	socket := &Socket{
		rt:            rt,
		conn:          conn,
		eventHandlers: make(map[string][]sobek.Callable),
		done:          make(chan struct{}),
	}
	defer func() { _ = socket.closeConn(websocket.CloseGoingAway) }()

	setupFn(socket)
	socket.fire("open")

	readCh := make(chan []byte)
	readErrCh := make(chan error)
	go socket.readPump(readCh, readErrCh)

	for {
		select {
		case msg := <-readCh:
			socket.fire("message", rt.ToValue(string(msg)))
		case readErr := <-readErrCh:
			if readErr != nil {
				socket.fire("error", rt.ToValue(readErr.Error()))
			}
			_ = socket.closeConn(websocket.CloseGoingAway)
			return &ConnectResult{Status: status}, nil
		case <-socket.done:
			return &ConnectResult{Status: status}, nil
		case <-ctx.Done():
			_ = socket.closeConn(websocket.CloseGoingAway)
			return &ConnectResult{Status: status}, nil
		}
	}
}

// On registers an event handler (open, message, close, error).
func (s *Socket) On(event string, handler sobek.Value) {
	if fn, ok := sobek.AssertFunction(handler); ok {
		s.eventHandlers[event] = append(s.eventHandlers[event], fn)
	}
}

// Send writes a text frame.
func (s *Socket) Send(message string) {
	if err := s.conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
		s.fire("error", s.rt.ToValue(err.Error()))
	}
}

// Close closes the connection.
func (s *Socket) Close(args ...sobek.Value) {
	c := websocket.CloseGoingAway
	if len(args) > 0 {
		c = int(args[0].ToInteger())
	}
	_ = s.closeConn(c)
}

func (s *Socket) fire(event string, args ...sobek.Value) {
	for _, h := range s.eventHandlers[event] {
		if _, err := h(sobek.Undefined(), args...); err != nil {
			common.Throw(s.rt, err)
		}
	}
}

func (s *Socket) closeConn(code int) error {
	var err error
	s.shutdownOnce.Do(func() {
		defer func() {
			_ = s.conn.Close()
			close(s.done)
		}()
		err = s.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(code, ""),
			time.Now().Add(writeWait),
		)
		if err != nil {
			s.fire("error", s.rt.ToValue(err.Error()))
		}
		s.fire("close", s.rt.ToValue(code))
	})
	return err
}

func (s *Socket) readPump(readCh chan []byte, errCh chan error) {
	for {
		_, data, err := s.conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				select {
				case errCh <- err:
				case <-s.done:
				}
			}
			select {
			case errCh <- nil:
			case <-s.done:
			}
			return
		}
		select {
		case readCh <- data:
		case <-s.done:
			return
		}
	}
}

func parseParams(params map[string]any, state *lib.State) (*connectParams, error) {
	p := &connectParams{
		headers: make(http.Header),
	}
	if state.Options.UserAgent.String != "" {
		p.headers.Set("User-Agent", state.Options.UserAgent.String)
	}
	if params == nil {
		return p, nil
	}
	if v, ok := params["tlsAuth"]; ok {
		p.tlsAuth = v
	}
	if v, ok := params["headers"].(map[string]any); ok {
		for k, val := range v {
			if s, ok := val.(string); ok {
				p.headers.Set(k, s)
			}
		}
	}
	if v, ok := params["headers"].(map[string]string); ok {
		for k, val := range v {
			p.headers.Set(k, val)
		}
	}
	if v, ok := params["tags"].(map[string]any); ok {
		p.tags = make(map[string]string, len(v))
		for k, val := range v {
			if s, ok := val.(string); ok {
				p.tags[k] = s
			}
		}
	}
	return p, nil
}

func buildTLSConfig(state *lib.State, tlsAuthVal any) (*tls.Config, error) {
	var tlsConfig *tls.Config
	if state.TLSConfig != nil {
		tlsConfig = state.TLSConfig.Clone()
	} else {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.NextProtos = []string{"http/1.1"}
	if state.Options.InsecureSkipTLSVerify.Valid && state.Options.InsecureSkipTLSVerify.Bool {
		tlsConfig.InsecureSkipVerify = true
	}
	if tlsAuthVal != nil {
		cert, err := tlsauth.Parse(tlsAuthVal)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}
	return tlsConfig, nil
}
