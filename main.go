package main

import (
	_ "github.com/lyft/protoc-gen-star"
	pgs "github.com/lyft/protoc-gen-star"
	_ "github.com/lyft/protoc-gen-star/lang/go"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"

	"github.com/autom8ter/protoc-gen-authorize/module"
)

func main() {
	pgs.Init(pgs.DebugEnv("AUTHORIZE_DEBUG")).
		RegisterModule(module.New()).
		RegisterPostProcessor(pgsgo.GoFmt()).
		Render()
}
