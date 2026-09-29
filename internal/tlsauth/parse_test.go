package tlsauth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/XavierChevalier/xk6-tlsauth/internal/tlsauth"
)

func TestParseRejectsNonObject(t *testing.T) {
	t.Parallel()
	_, err := tlsauth.Parse("nope")
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be an object")
}

func TestParseRejectsMissingCert(t *testing.T) {
	t.Parallel()
	_, err := tlsauth.Parse(map[string]any{"key": "x"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "tlsAuth.cert")
}

func TestParseRejectsMissingKey(t *testing.T) {
	t.Parallel()
	_, err := tlsauth.Parse(map[string]any{"cert": "x"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "tlsAuth.key")
}

func TestParseRejectsNonStringPassword(t *testing.T) {
	t.Parallel()
	_, err := tlsauth.Parse(map[string]any{
		"cert":     "x",
		"key":      "y",
		"password": 1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "tlsAuth.password")
}
