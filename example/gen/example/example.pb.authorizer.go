package example

import (
	"github.com/autom8ter/protoc-gen-authorize/authorizer"
	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
)

func NewJavascriptAuthorizer() (*authorizer.JavascriptAuthorizer, error) {
	return authorizer.NewJavascriptAuthorizer(map[string]*authorize.RuleSet{
		ExampleService_ExampleMethod1_FullMethodName: {
			Rules: []*authorize.Rule{
				{
					Expression: "user.AccountIds.includes(request.AccountId) && user.Roles.includes('admin')",
				},
				{
					Expression: "user.IsSuperAdmin",
				},
			},
		},
		ExampleService_ExampleMethod2_FullMethodName: {
			Rules: []*authorize.Rule{
				{
					Expression: "user.AccountIds.includes(metadata['x-account-id']) && user.Roles.includes('admin')",
				},
				{
					Expression: "user.IsSuperAdmin",
				},
			},
		},
	})
}
