package http

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/require"
	"go.k6.io/k6/v2/js/modules"
	"go.k6.io/k6/v2/js/modulestest"
	"go.k6.io/k6/v2/lib"
	"go.k6.io/k6/v2/metrics"
	"gopkg.in/guregu/null.v3"
)

func testVU(t *testing.T) modules.VU {
	vu := &modulestest.VU{
		CtxField:     t.Context(),
		RuntimeField: sobek.New(),
	}
	reg := metrics.NewRegistry()
	vu.StateField = &lib.State{
		Options: lib.Options{
			InsecureSkipTLSVerify: null.BoolFrom(true),
		},
		Dialer:         &net.Dialer{},
		Tags:           lib.NewVUStateTags(reg.RootTagSet()),
		BuiltinMetrics: metrics.RegisterBuiltinMetrics(reg),
		Samples:        make(chan metrics.SampleContainer, 10),
	}
	return vu
}

func startMTLSServer(t *testing.T) (url string, clientCertPEM, clientKeyPEM []byte) {
	t.Helper()

	caCertPEM, caKeyPEM := generateTLSCertificate(t, "127.0.0.1", time.Now(), time.Hour)
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	require.NoError(t, err)
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKeyAny, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	require.NoError(t, err)
	caKey := caKeyAny.(*rsa.PrivateKey)

	srvCertPEM, srvKeyPEM := generateTLSCertificateWithCA(t, "127.0.0.1", time.Now(), time.Hour, caCert, caKey)
	clientCertPEM, clientKeyPEM = generateTLSCertificateWithCA(t, "127.0.0.1", time.Now(), time.Hour, caCert, caKey)

	clientCAPool := x509.NewCertPool()
	require.True(t, clientCAPool.AppendCertsFromPEM(caCertPEM))

	serverCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
	})
	require.NoError(t, err)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, "ok")
		}),
		ErrorLog: nil,
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = listener.Close() })

	return "https://" + listener.Addr().String(), clientCertPEM, clientKeyPEM
}

func TestHTTPGetWithTLSAuth(t *testing.T) {
	t.Parallel()

	serverURL, clientCertPEM, clientKeyPEM := startMTLSServer(t)
	c := NewClient(testVU(t))

	res, err := c.Get(serverURL, map[string]any{
		"tlsAuth": map[string]any{
			"cert": string(clientCertPEM),
			"key":  string(clientKeyPEM),
		},
	})
	require.NoError(t, err)
	require.Equal(t, 200, res.Status)
	require.Equal(t, "ok", res.Body)
	require.Empty(t, res.Error)
}

type countingDialer struct {
	inner lib.DialContexter
	n     *int
	mu    *sync.Mutex
}

func (d *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	*d.n++
	d.mu.Unlock()
	return d.inner.DialContext(ctx, network, addr)
}

func TestTransportPoolReusesDialForSameTLSAuth(t *testing.T) {
	t.Parallel()

	serverURL, clientCertPEM, clientKeyPEM := startMTLSServer(t)
	vu := testVU(t)
	var dials int
	var dialMu sync.Mutex
	vu.State().Dialer = &countingDialer{inner: vu.State().Dialer, n: &dials, mu: &dialMu}

	c := NewClient(vu)
	params := map[string]any{
		"tlsAuth": map[string]any{
			"cert": string(clientCertPEM),
			"key":  string(clientKeyPEM),
		},
	}

	res1, err := c.Get(serverURL, params)
	require.NoError(t, err)
	require.Equal(t, 200, res1.Status)

	dialMu.Lock()
	afterFirst := dials
	dialMu.Unlock()
	require.Equal(t, 1, afterFirst)
	require.Equal(t, 1, c.pooledTransportCount())

	res2, err := c.Get(serverURL, params)
	require.NoError(t, err)
	require.Equal(t, 200, res2.Status)

	dialMu.Lock()
	afterSecond := dials
	dialMu.Unlock()
	require.Equal(t, 1, afterSecond, "expected keep-alive reuse of pooled transport")
	require.Equal(t, 1, c.pooledTransportCount())
}

func TestTransportPoolKeepsSeparateTransportsPerCert(t *testing.T) {
	t.Parallel()

	serverURL, certAPEM, keyAPEM, certBPEM, keyBPEM := startMTLSServerReportingClientCN(t)
	c := NewClient(testVU(t))

	_, err := c.Get(serverURL, map[string]any{
		"tlsAuth": map[string]any{"cert": string(certAPEM), "key": string(keyAPEM)},
	})
	require.NoError(t, err)
	_, err = c.Get(serverURL, map[string]any{
		"tlsAuth": map[string]any{"cert": string(certBPEM), "key": string(keyBPEM)},
	})
	require.NoError(t, err)
	require.Equal(t, 2, c.pooledTransportCount())
}

func startMTLSServerReportingClientCN(t *testing.T) (url string, certAPEM, keyAPEM, certBPEM, keyBPEM []byte) {
	t.Helper()

	caCertPEM, caKeyPEM := generateTLSCertificate(t, "127.0.0.1", time.Now(), time.Hour)
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	require.NoError(t, err)
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKeyAny, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	require.NoError(t, err)
	caKey := caKeyAny.(*rsa.PrivateKey)

	srvCertPEM, srvKeyPEM := generateTLSCertificateWithCA(t, "127.0.0.1", time.Now(), time.Hour, caCert, caKey)
	certAPEM, keyAPEM = generateClientCertWithCA(t, "A", time.Now(), time.Hour, caCert, caKey)
	certBPEM, keyBPEM = generateClientCertWithCA(t, "B", time.Now(), time.Hour, caCert, caKey)

	clientCAPool := x509.NewCertPool()
	require.True(t, clientCAPool.AppendCertsFromPEM(caCertPEM))

	serverCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
	})
	require.NoError(t, err)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cn := ""
			if len(r.TLS.PeerCertificates) > 0 {
				cn = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			_, _ = fmt.Fprint(w, cn)
		}),
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = listener.Close() })

	return "https://" + listener.Addr().String(), certAPEM, keyAPEM, certBPEM, keyBPEM
}

func TestHTTPSwitchClientCertBetweenCalls(t *testing.T) {
	t.Parallel()

	serverURL, certAPEM, keyAPEM, certBPEM, keyBPEM := startMTLSServerReportingClientCN(t)
	c := NewClient(testVU(t))

	resA, err := c.Get(serverURL, map[string]any{
		"tlsAuth": map[string]any{
			"cert": string(certAPEM),
			"key":  string(keyAPEM),
		},
	})
	require.NoError(t, err)
	require.Equal(t, 200, resA.Status)
	require.Equal(t, "A", resA.Body)

	resB, err := c.Get(serverURL, map[string]any{
		"tlsAuth": map[string]any{
			"cert": string(certBPEM),
			"key":  string(keyBPEM),
		},
	})
	require.NoError(t, err)
	require.Equal(t, 200, resB.Status)
	require.Equal(t, "B", resB.Body)
}

func TestJSPostWithoutBodyOmitsUndefinedString(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var sawBody []byte
	srv := httptestPlainPOSTServer(t, &mu, &sawBody)

	vu := testVU(t)
	rt := vu.Runtime()
	mi := New().NewModuleInstance(vu)
	require.NoError(t, rt.Set("http", mi.Exports().Default))

	_, err := rt.RunString(fmt.Sprintf(`http.post("%s")`, srv))
	require.NoError(t, err)

	mu.Lock()
	body := append([]byte(nil), sawBody...)
	mu.Unlock()
	require.Empty(t, body)
}

func TestHTTPNetworkErrorRespectsThrowOption(t *testing.T) {
	t.Parallel()

	vu := testVU(t)
	vu.State().Options.Throw = null.BoolFrom(true)
	c := NewClient(vu)

	_, err := c.Get("http://127.0.0.1:1", nil)
	require.Error(t, err)

	vu.State().Options.Throw = null.BoolFrom(false)
	res, err := c.Get("http://127.0.0.1:1", nil)
	require.NoError(t, err)
	require.NotEmpty(t, res.Error)
	require.Equal(t, 0, res.Status)
}

func TestHTTPGetMissingTLSAuthFails(t *testing.T) {
	t.Parallel()

	serverURL, _, _ := startMTLSServer(t)
	c := NewClient(testVU(t))

	res, err := c.Get(serverURL, nil)
	require.NoError(t, err)
	require.Equal(t, 0, res.Status)
	require.NotEmpty(t, res.Error)
}

func httptestPlainPOSTServer(t *testing.T, mu *sync.Mutex, sawBody *[]byte) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := io.ReadAll(r.Body)
			mu.Lock()
			*sawBody = data
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = listener.Close() })

	return "http://" + listener.Addr().String()
}

func generateTLSCertificate(t *testing.T, host string, notBefore time.Time, validFor time.Duration) ([]byte, []byte) {
	return generateTLSCertificateWithCA(t, host, notBefore, validFor, nil, nil)
}

func generateTLSCertificateWithCA(
	t *testing.T, host string, notBefore time.Time, validFor time.Duration,
	parent *x509.Certificate, ppriv *rsa.PrivateKey,
) ([]byte, []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	notAfter := notBefore.Add(validFor)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Acme Co"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	for h := range strings.SplitSeq(host, ",") {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if parent == nil {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		parent = &template
		ppriv = priv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &priv.PublicKey, ppriv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	return certPEM, keyPEM
}

func generateClientCertWithCA(
	t *testing.T, commonName string, notBefore time.Time, validFor time.Duration,
	parent *x509.Certificate, ppriv *rsa.PrivateKey,
) ([]byte, []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	notAfter := notBefore.Add(validFor)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &priv.PublicKey, ppriv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	return certPEM, keyPEM
}
