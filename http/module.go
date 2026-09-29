package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"go.k6.io/k6/v2/js/common"
	"go.k6.io/k6/v2/js/modules"
	"go.k6.io/k6/v2/lib/types"
	"go.k6.io/k6/v2/metrics"

	"github.com/XavierChevalier/xk6-tlsauth/internal/tlsauth"
)

func init() {
	modules.Register("k6/x/tlsauth/http", New())
}

// RootModule is registered once per test run.
type RootModule struct{}

// ModuleInstance is the per-VU HTTP extension instance.
type ModuleInstance struct {
	vu     modules.VU
	client *Client
}

// Client performs one-shot HTTP requests with per-request tlsAuth.
type Client struct {
	vu modules.VU
}

// Response is returned to JS and Go callers.
type Response struct {
	Status  int
	Body    string
	Headers map[string]string
	Error   string
}

type requestParams struct {
	tlsAuth any
	headers map[string]string
	timeout time.Duration
	tags    map[string]string
}

const defaultHTTPTimeout = 60 * time.Second

var (
	_ modules.Module   = &RootModule{}
	_ modules.Instance = &ModuleInstance{}
)

// New returns the root module.
func New() *RootModule {
	return &RootModule{}
}

// NewClient builds a client for the given VU (tests and internal use).
func NewClient(vu modules.VU) *Client {
	return &Client{vu: vu}
}

// NewModuleInstance implements modules.Module.
func (r *RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	mi := &ModuleInstance{
		vu:     vu,
		client: NewClient(vu),
	}
	return mi
}

// Exports implements modules.Instance.
func (mi *ModuleInstance) Exports() modules.Exports {
	rt := mi.vu.Runtime()
	obj := rt.NewObject()
	client := mi.client
	export := func(name string, fn any) {
		if err := obj.Set(name, fn); err != nil {
			common.Throw(rt, err)
		}
	}
	export("get", func(call sobek.FunctionCall) sobek.Value {
		url := call.Argument(0).String()
		params := jsParams(call, 1)
		res, err := client.Get(url, params)
		if err != nil {
			common.Throw(rt, err)
		}
		return rt.ToValue(res)
	})
	export("post", func(call sobek.FunctionCall) sobek.Value {
		url := call.Argument(0).String()
		body := jsBodyArg(call, 1)
		params := jsParams(call, 2)
		res, err := client.Post(url, body, params)
		if err != nil {
			common.Throw(rt, err)
		}
		return rt.ToValue(res)
	})
	export("request", func(call sobek.FunctionCall) sobek.Value {
		method := call.Argument(0).String()
		url := call.Argument(1).String()
		body := jsBodyArg(call, 2)
		params := jsParams(call, 3)
		res, err := client.Request(method, url, body, params)
		if err != nil {
			common.Throw(rt, err)
		}
		return rt.ToValue(res)
	})
	return modules.Exports{Default: obj}
}

func jsBodyArg(call sobek.FunctionCall, idx int) string {
	if idx >= len(call.Arguments) || common.IsNullish(call.Argument(idx)) {
		return ""
	}
	return call.Argument(idx).String()
}

func jsParams(call sobek.FunctionCall, idx int) map[string]any {
	if idx >= len(call.Arguments) || common.IsNullish(call.Argument(idx)) {
		return nil
	}
	v := call.Argument(idx).Export()
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// Get performs an HTTP GET.
func (c *Client) Get(url string, params map[string]any) (*Response, error) {
	return c.Request(http.MethodGet, url, "", params)
}

// Post performs an HTTP POST.
func (c *Client) Post(url, body string, params map[string]any) (*Response, error) {
	return c.Request(http.MethodPost, url, body, params)
}

// Request performs an HTTP request with optional per-request tlsAuth.
func (c *Client) Request(method, url, body string, params map[string]any) (*Response, error) {
	p, err := parseParams(params)
	if err != nil {
		return nil, err
	}

	ctx := c.vu.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	tlsConfig, err := c.buildTLSConfig(p.tlsAuth)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	defer transport.CloseIdleConnections()
	if state := c.vu.State(); state != nil {
		if state.Dialer != nil {
			transport.DialContext = state.Dialer.DialContext
		} else if tr, ok := state.Transport.(*http.Transport); ok && tr.DialContext != nil {
			transport.DialContext = tr.DialContext
		}
	}

	client := &http.Client{Transport: transport, Timeout: defaultHTTPTimeout}
	if p.timeout > 0 {
		client.Timeout = p.timeout
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}

	resp, doErr := client.Do(req)
	if doErr != nil {
		if state := c.vu.State(); state != nil && state.Options.Throw.Valid && state.Options.Throw.Bool {
			return nil, doErr
		}
		return &Response{Status: 0, Error: doErr.Error()}, nil
	}
	defer resp.Body.Close()

	data, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return &Response{Status: resp.StatusCode, Error: readErr.Error()}, nil
	}

	res := &Response{
		Status:  resp.StatusCode,
		Body:    string(data),
		Headers: flattenHeaders(resp.Header),
	}
	c.pushMetrics(ctx, p.tags, res.Status)
	return res, nil
}

func (c *Client) buildTLSConfig(tlsAuthVal any) (*tls.Config, error) {
	var tlsConfig *tls.Config
	if state := c.vu.State(); state != nil && state.TLSConfig != nil {
		tlsConfig = state.TLSConfig.Clone()
	} else {
		tlsConfig = &tls.Config{}
	}
	if state := c.vu.State(); state != nil &&
		state.Options.InsecureSkipTLSVerify.Valid && state.Options.InsecureSkipTLSVerify.Bool {
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

func parseParams(params map[string]any) (*requestParams, error) {
	p := &requestParams{}
	if params == nil {
		return p, nil
	}
	if v, ok := params["tlsAuth"]; ok {
		p.tlsAuth = v
	}
	if v, ok := params["headers"].(map[string]any); ok {
		p.headers = make(map[string]string, len(v))
		for k, val := range v {
			if s, ok := val.(string); ok {
				p.headers[k] = s
			}
		}
	}
	if v, ok := params["headers"].(map[string]string); ok {
		p.headers = v
	}
	if v, ok := params["timeout"]; ok && v != nil {
		d, err := types.GetDurationValue(v)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
		p.timeout = d
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

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

func (c *Client) pushMetrics(ctx context.Context, tags map[string]string, status int) {
	state := c.vu.State()
	if state == nil || state.BuiltinMetrics == nil || state.Samples == nil {
		return
	}
	tm := metrics.TagsAndMeta{}
	if state.Tags != nil {
		tm = state.Tags.GetCurrentValues()
	}
	if tm.Tags == nil {
		return
	}
	for k, v := range tags {
		tm.SetTag(k, v)
	}
	if status > 0 {
		tm.SetSystemTagOrMeta(metrics.TagStatus, fmt.Sprintf("%d", status))
	}
	_ = metrics.PushIfNotDone(ctx, state.Samples, metrics.Sample{
		TimeSeries: metrics.TimeSeries{
			Metric: state.BuiltinMetrics.HTTPReqs,
			Tags:   tm.Tags,
		},
		Time:     time.Now(),
		Metadata: tm.Metadata,
		Value:    1,
	})
}
