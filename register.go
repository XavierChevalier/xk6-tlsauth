package tlsauth

import (
	"go.k6.io/k6/v2/js/modules"
)

func init() {
	modules.Register("k6/x/tlsauth/http", new(httpRoot))
	modules.Register("k6/x/tlsauth/ws", new(wsRoot))
}

// Placeholders replaced in Tasks 2–3 with real constructors from http/ and ws/ packages.
// Prefer moving Register calls into http/module.go and ws/module.go init() and keeping
// this file as blank imports if that compiles more cleanly with xk6:

// import (
//   _ "github.com/XavierChevalier/xk6-tlsauth/http"
//   _ "github.com/XavierChevalier/xk6-tlsauth/ws"
// )

type httpRoot struct{}
type wsRoot struct{}

func (*httpRoot) NewModuleInstance(vu modules.VU) modules.Instance {
	return &emptyInstance{}
}
func (*wsRoot) NewModuleInstance(vu modules.VU) modules.Instance {
	return &emptyInstance{}
}

type emptyInstance struct{}

func (*emptyInstance) Exports() modules.Exports {
	return modules.Exports{Default: map[string]any{}}
}
