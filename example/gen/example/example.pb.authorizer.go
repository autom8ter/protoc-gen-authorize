package example

import (
	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
)

var AuthorizationRules = map[string]*authorize.RuleSet{
	ExampleService_ExampleMethod1_FullMethodName: {
		Rules: []*authorize.Rule{
			{
				Expression: "request.StrValue == 'hello'",
			},
		},
	},
}
