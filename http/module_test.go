package http

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
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

func TestHTTPGetMissingTLSAuthFails(t *testing.T) {
	t.Parallel()

	serverURL, _, _ := startMTLSServer(t)
	c := NewClient(testVU(t))

	res, err := c.Get(serverURL, nil)
	require.NoError(t, err)
	require.Equal(t, 0, res.Status)
	require.NotEmpty(t, res.Error)
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
