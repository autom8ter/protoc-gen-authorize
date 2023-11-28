package javascript_test

import (
	"context"
	"testing"

	"github.com/autom8ter/protoc-gen-authorize/authorizer"
	"github.com/autom8ter/protoc-gen-authorize/authorizer/javascript"
	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
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
						Expression: "request.GetStrVal() == 'hello' && request.Int64Val == 1",
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
						Expression: "user.Roles.includes('admin')",
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
						Expression: "user.Roles.includes('admin')",
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
						Expression: "user.Roles.includes('guest') && request.StrVal == 'hello'",
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
						Expression: "user.Roles.includes('guest') && request.StrVal == 'hello'",
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
						Expression: "user.Roles.includes('admin') && user.Accounts.includes(request.StrVal)",
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
						Expression: "user.Roles.includes('admin') && user.Accounts.includes(request.StrVal)",
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
						Expression: "user.Roles.includes('admin') && user.Accounts.includes(metadata['x-account-id'])",
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
						Expression: "user.Roles.includes('admin') && user.Accounts.includes(metadata['x-account-id'])",
					},
				},
			},
		},
		expectAllow: false,
	},
	{
		name:   "missing rule for method 8 (deny)",
		method: "testing1",
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
						Expression: "user.Roles.includes('admin') && user.Accounts.includes(metadata['x-account-id'])",
					},
				},
			},
		},
		expectAllow: false,
	},
}

func TestJavascriptAuthorizer_AuthorizeMethod(t *testing.T) {
	ctx := context.Background()
	for _, fix := range fixtures {
		t.Run(fix.name, func(t *testing.T) {
			if fix.method == "" {
				t.Fatalf("method is required")
			}
			authz, err := javascript.NewJavascriptAuthorizer(fix.rules)
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
BenchmarkJavascriptAuthorizer_AuthorizeMethod
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_request_field_rule_1_(allow)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_request_field_rule_1_(allow)-8         	   96181	     11314 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_1_(allow)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_1_(allow)-8       	  102724	     13171 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_2_(deny)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_2_(deny)-8        	   98842	     11629 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_3_(allow)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_3_(allow)-8       	   97920	     12050 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_3_(allow)#01
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_3_(allow)#01-8    	   94418	     12188 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_4_(allow)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_4_(allow)-8       	   82056	     14589 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_5_(deny)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_rule_5_(deny)-8        	   74192	     15363 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_w/_metadata_check_rule_6_(allow)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_w/_metadata_check_rule_6_(allow)-8         	   82628	     14216 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_w/_metadata_check_rule_7_(deny)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/basic_user_expression_w/_metadata_check_rule_7_(deny)-8          	   77010	     15712 ns/op
BenchmarkJavascriptAuthorizer_AuthorizeMethod/missing_rule_for_method_8_(deny)
BenchmarkJavascriptAuthorizer_AuthorizeMethod/missing_rule_for_method_8_(deny)-8                              	152635189	         7.879 ns/op
*/
func BenchmarkJavascriptAuthorizer_AuthorizeMethod(b *testing.B) {
	ctx := context.Background()
	for _, fix := range fixtures {
		b.Run(fix.name, func(b *testing.B) {
			if fix.method == "" {
				b.Fatalf("method is required")
			}
			authz, err := javascript.NewJavascriptAuthorizer(fix.rules)
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
