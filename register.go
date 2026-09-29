package tlsauth

import (
	_ "github.com/XavierChevalier/xk6-tlsauth/http"

	"go.k6.io/k6/v2/js/modules"
)

func init() {
	modules.Register("k6/x/tlsauth/ws", new(wsRoot))
}

type wsRoot struct{}

func (*wsRoot) NewModuleInstance(vu modules.VU) modules.Instance {
	return &emptyInstance{}
}

type emptyInstance struct{}

func (*emptyInstance) Exports() modules.Exports {
	return modules.Exports{Default: map[string]any{}}
}
