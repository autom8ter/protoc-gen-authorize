package cel_test

import (
	"context"
	"testing"

	"github.com/autom8ter/proto/gen/authorize"

	"github.com/autom8ter/protoc-gen-authorize/authorizer"
	"github.com/autom8ter/protoc-gen-authorize/authorizer/cel"
)

type fixture struct {
	name        string
	method      string
	opts        []authorizer.Opt
	rules       map[string]*authorize.RuleSet
	params      *authorizer.RuleExecutionParams
	expectError bool
	expectAllow bool
}

type Request struct {
	StrVal    string
	StrsVal   []string
	Int64Val  int64
	Ints64Val []int64
	FloatVal  float64
	FloatsVal []float64
	BoolVal   bool
	BoolsVal  []bool
}

func (r *Request) GetStrVal() string {
	return r.StrVal
}

func (r *Request) GetStrsVal() []string {
	return r.StrsVal
}

type User struct {
	Roles       []string
	IsSuperUser bool
	Accounts    []string
}

var fixtures = []fixture{
	{
		name:   "basic request field rule 1 (allow)",
		method: "testing",
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "request.StrVal == 'hello' && request.Int64Val == 1",
					},
				},
			},
		},
		params: &authorizer.RuleExecutionParams{
			Request: &Request{
				StrVal:   "hello",
				Int64Val: 1,
			},
		},
		expectAllow: true,
	},
	{
		name:   "basic user expression rule 1 (allow)",
		method: "testing",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles: []string{"admin"},
			},
			Request: &Request{
				StrVal:   "hello",
				Int64Val: 1,
			},
		},
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'admin' in user.Roles",
					},
				},
			},
		},
		expectAllow: true,
	},
	{
		name:   "basic user expression rule 2 (deny)",
		method: "testing",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles: []string{"guest"},
			},
			Request: &Request{
				StrVal:   "hello",
				Int64Val: 1,
			},
		},
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'admin' in user.Roles",
					},
				},
			},
		},
		expectAllow: false,
	},
	{
		name:   "basic user expression rule 3 (allow)",
		method: "testing",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles: []string{"guest"},
			},
			Request: &Request{
				StrVal:   "hello",
				Int64Val: 1,
			},
		},
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'guest' in user.Roles && request.StrVal == 'hello'",
					},
				},
			},
		},
		expectAllow: true,
	},
	{
		name:   "basic user expression rule 3 (allow)",
		method: "testing",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles: []string{"guest"},
			},
			Request: &Request{
				StrVal:   "hello",
				Int64Val: 1,
			},
		},
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'guest' in user.Roles && request.StrVal == 'hello'",
					},
				},
			},
		},
		expectAllow: true,
	},
	{
		name:   "basic user expression rule 4 (allow)",
		method: "testing",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles:    []string{"admin"},
				Accounts: []string{"8"},
			},
			Request: &Request{
				StrVal: "8",
			},
		},
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'admin' in user.Roles && request.StrVal in user.Accounts",
					},
				},
			},
		},
		expectAllow: true,
	},
	{
		name:   "basic user expression rule 5 (deny)",
		method: "testing",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles:    []string{"admin"},
				Accounts: []string{"7", "6", "5", "4", "3", "2", "1"},
			},
			Request: &Request{
				StrVal: "8",
			},
		},
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'admin' in user.Roles && request.StrVal in user.Accounts",
					},
				},
			},
		},
		expectAllow: false,
	},
	{
		name:   "basic user expression w/ metadata check rule 6 (allow)",
		method: "testing",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles:    []string{"admin"},
				Accounts: []string{"8", "7", "6", "5", "4", "3", "2", "1"},
			},
			Request: &Request{
				StrVal: "hello world",
			},
			Metadata: map[string][]string{
				"x-account-id": {"8"},
			},
		},
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'admin' in user.Roles && metadata['x-account-id'] in user.Accounts",
					},
				},
			},
		},
		expectAllow: true,
	},
	{
		name:   "basic user expression w/ metadata check rule 7 (deny)",
		method: "testing",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles:    []string{"admin"},
				Accounts: []string{"7", "6", "5", "4", "3", "2", "1"},
			},
			Request: &Request{
				StrVal: "hello world",
			},
			Metadata: map[string][]string{
				"x-account-id": {"8"},
			},
		},
		rules: map[string]*authorize.RuleSet{
			"testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'admin' in user.Roles && metadata['x-account-id'] in user.Accounts",
					},
				},
			},
		},
		expectAllow: false,
	},
	{
		name:   "missing rule for method 8 (allow)",
		method: "/svc/testing1",
		params: &authorizer.RuleExecutionParams{
			User: &User{
				Roles:    []string{"admin"},
				Accounts: []string{"7", "6", "5", "4", "3", "2", "1"},
			},
			Request: &Request{
				StrVal: "hello world",
			},
			Metadata: map[string][]string{
				"x-account-id": {"8"},
			},
		},
		rules: map[string]*authorize.RuleSet{
			"/svc/testing": {
				Rules: []*authorize.Rule{
					{
						Expression: "'admin' in user.Roles && metadata['x-account-id'] in user.Accounts",
					},
				},
			},
		},
		expectAllow: true,
	},
}

func TestCelAuthorizer_AuthorizeMethod(t *testing.T) {
	ctx := context.Background()
	for _, fix := range fixtures {
		t.Run(fix.name, func(t *testing.T) {
			if fix.method == "" {
				t.Fatalf("method is required")
			}
			authz, err := cel.NewCelAuthorizer(fix.rules)
			if fix.expectError {
				if err == nil {
					t.Fatalf("expected error")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			allow, err := authz.AuthorizeMethod(ctx, fix.method, fix.params)
			if fix.expectError {
				if err == nil {
					t.Fatalf("expected error")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			if fix.expectAllow {
				if !allow {
					t.Fatalf("expected allow")
				}
			} else {
				if allow {
					t.Fatalf("expected deny")
				}
			}
		})
	}
}

/*
BenchmarkCelAuthorizer_AuthorizeMethod
BenchmarkCelAuthorizer_AuthorizeMethod/basic_request_field_rule_1_(allow)
BenchmarkCelAuthorizer_AuthorizeMethod/basic_request_field_rule_1_(allow)-8         	  253653	      4274 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_1_(allow)
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_1_(allow)-8       	  228214	      5125 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_2_(deny)
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_2_(deny)-8        	  212444	      5132 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_3_(allow)
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_3_(allow)-8       	  189430	      5476 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_3_(allow)#01
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_3_(allow)#01-8    	  212554	      5820 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_4_(allow)
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_4_(allow)-8       	  201432	      6082 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_5_(deny)
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_rule_5_(deny)-8        	  176553	      7028 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_w/_metadata_check_rule_6_(allow)
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_w/_metadata_check_rule_6_(allow)-8         	  181896	      6293 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_w/_metadata_check_rule_7_(deny)
BenchmarkCelAuthorizer_AuthorizeMethod/basic_user_expression_w/_metadata_check_rule_7_(deny)-8          	  162328	      7133 ns/op
BenchmarkCelAuthorizer_AuthorizeMethod/missing_rule_for_method_8_(deny)
BenchmarkCelAuthorizer_AuthorizeMethod/missing_rule_for_method_8_(deny)-8                              	140655366	         7.879 ns/op
*/
func BenchmarkCelAuthorizer_AuthorizeMethod(b *testing.B) {
	ctx := context.Background()
	for _, fix := range fixtures {
		b.Run(fix.name, func(b *testing.B) {
			if fix.method == "" {
				b.Fatalf("method is required")
			}
			authz, err := cel.NewCelAuthorizer(fix.rules)
			if fix.expectError {
				if err == nil {
					b.Fatalf("expected error")
				}
			} else {
				if err != nil {
					b.Fatalf("unexpected error: %v", err)
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				allow, err := authz.AuthorizeMethod(ctx, fix.method, fix.params)
				if fix.expectError {
					if err == nil {
						b.Fatalf("expected error")
					}
				} else {
					if err != nil {
						b.Fatalf("unexpected error: %v", err)
					}
				}
				if fix.expectAllow {
					if !allow {
						b.Fatalf("expected allow")
					}
				} else {
					if allow {
						b.Fatalf("expected deny")
					}
				}
			}
		})
	}
}
