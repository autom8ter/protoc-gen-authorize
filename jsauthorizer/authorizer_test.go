package jsauthorizer_test

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/autom8ter/protoc-gen-authorize/authorizer"
	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
	"github.com/autom8ter/protoc-gen-authorize/jsauthorizer"
)

type fixture struct {
	name        string
	opts        []jsauthorizer.Opt
	rule        *authorize.Rule
	request     any
	metadata    metadata.MD
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

var fixtures = []fixture{
	{
		name: "basic request field rule 1 (allow)",
		rule: &authorize.Rule{
			Expression: "request.GetStrVal() == 'hello' && request.Int64Val == 1",
		},
		request: &Request{
			StrVal:   "hello",
			Int64Val: 1,
		},
		expectAllow: true,
	},
	{
		name: "basic request field rule 2 (deny)",
		rule: &authorize.Rule{
			Expression: "request.StrVal == 'hello' && request.Int64Val == 1",
		},
		request: &Request{
			StrVal: "hello",
		},
		expectAllow: false,
	},
	{
		name: "basic request field rule 3 (allow)",
		rule: &authorize.Rule{
			Expression: "request.StrVal == 'hello' && request.Ints64Val.includes(1)",
		},
		request: &Request{
			StrVal:    "hello",
			Int64Val:  1,
			Ints64Val: []int64{1},
		},
		expectAllow: true,
	},
	{
		name: "basic request field rule 4 (deny)",
		rule: &authorize.Rule{
			Expression: "request.StrVal == 'hello' && !request.Ints64Val.includes(1)",
		},
		request: &Request{
			StrVal:    "hello",
			Int64Val:  1,
			Ints64Val: []int64{1},
		},
		expectAllow: false,
	},
	{
		name: "basic request field rule 5 (deny)",
		rule: &authorize.Rule{
			Expression: "request.StrVal == 'hello' && !request.Ints64Val.includes(1)",
		},
		request: &Request{
			StrVal:    "hello",
			Int64Val:  1,
			Ints64Val: []int64{1},
		},
		expectAllow: false,
	},
}

func TestAuthorizer(t *testing.T) {
	ctx := context.Background()
	for _, fix := range fixtures {
		t.Run(fix.name, func(t *testing.T) {
			authz, err := jsauthorizer.New(fix.opts...)
			if fix.expectError {
				if err == nil {
					t.Fatalf("expected error")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			usr, err := authz.ExtractUser(ctx)
			if fix.expectError {
				if err == nil {
					t.Fatalf("expected error")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			allow, err := authz.ExecuteRule(ctx, fix.rule, &authorizer.RuleExecutionParams{
				User:     usr,
				Request:  fix.request,
				Metadata: fix.metadata,
				IsStream: false,
			})
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
