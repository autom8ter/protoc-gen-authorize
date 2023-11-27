package example

import (
	"github.com/autom8ter/protoc-gen-authorize/authorizer/javascript"
	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
)

// NewAuthorizer returns a new javascript authorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewAuthorizer() (*javascript.JavascriptAuthorizer, error) {
	return javascript.NewJavascriptAuthorizer(map[string]*authorize.RuleSet{
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
