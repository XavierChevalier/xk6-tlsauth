package tlsauth

import (
	"crypto/tls"
	"fmt"

	"gopkg.in/guregu/null.v3"

	"go.k6.io/k6/v2/lib"
)

// Parse builds a client certificate from a JS tlsAuth object:
// { cert: string, key: string, password?: string }.
func Parse(v any) (*tls.Certificate, error) {
	raw, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tlsAuth must be an object, got %T", v)
	}
	certStr, ok := raw["cert"].(string)
	if !ok || certStr == "" {
		return nil, fmt.Errorf("tlsAuth.cert must be a non-empty PEM string")
	}
	keyStr, ok := raw["key"].(string)
	if !ok || keyStr == "" {
		return nil, fmt.Errorf("tlsAuth.key must be a non-empty PEM string")
	}
	auth := &lib.TLSAuth{
		TLSAuthFields: lib.TLSAuthFields{
			Cert: certStr,
			Key:  keyStr,
		},
	}
	if password, exists := raw["password"]; exists && password != nil {
		passwordStr, ok := password.(string)
		if !ok {
			return nil, fmt.Errorf("tlsAuth.password must be a string")
		}
		auth.Password = null.StringFrom(passwordStr)
	}
	return auth.Certificate()
}
