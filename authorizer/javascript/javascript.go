package javascript

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/dop251/goja"

	"github.com/autom8ter/proto/gen/authorize"

	"github.com/autom8ter/protoc-gen-authorize/authorizer"
)

// Opt is a functional option for configuring a JavascriptAuthorizer
type Opt func(*JavascriptAuthorizer)

// WithVariables sets additional variables/functions that will be available to the javascript vm
func WithVariables(variables map[string]any) Opt {
	return func(a *JavascriptAuthorizer) {
		for k, v := range variables {
			a.variables[k] = v
		}
	}
}

// JavascriptAuthorizer is a javascript vm that uses javascript expressions to authorize grpc requests
type JavascriptAuthorizer struct {
	rules          map[string]*authorize.RuleSet
	cachedPrograms sync.Map
	variables      map[string]any
}

// NewJavascriptAuthorizer returns a new JavascriptAuthorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewJavascriptAuthorizer(rules map[string]*authorize.RuleSet, opts ...Opt) (*JavascriptAuthorizer, error) {
	a := &JavascriptAuthorizer{
		rules:          rules,
		cachedPrograms: sync.Map{},
		variables:      map[string]any{},
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// AuthorizeMethod authorizes a gRPC method the RuleExecutionParams and returns a boolean representing whether the
// request is authorized or not.
func (a *JavascriptAuthorizer) AuthorizeMethod(ctx context.Context, method string, params *authorizer.RuleExecutionParams) (bool, error) {
	// return false if no rules exist for the method
	rules, ok := a.rules[method]
	if !ok {
		svc := strings.Split(method, "/")[1]
		for k, _ := range a.rules {
			if strings.HasPrefix(k, "/"+svc) {
				return true, nil
			}
		}
		return false, nil
	}
	// allow all
	if len(rules.Rules) == 1 && rules.Rules[0].Expression == "*" {
		return true, nil
	}
	programs, err := a.getMethodPrograms(rules)
	if err != nil {
		return false, err
	}
	vm := goja.New()
	for k, v := range a.variables {
		if err := vm.Set(k, v); err != nil {
			return false, fmt.Errorf("authorizer: failed to set variable: %v", err.Error())
		}
	}
	var (
		metaMap = map[string]string{}
	)
	for k, v := range params.Metadata {
		metaMap[k] = strings.Join(v, ",")
	}
	if err := vm.Set(string(authorizer.ExpressionVarMetadata), metaMap); err != nil {
		return false, fmt.Errorf("authorizer: failed to set metadata: %v", err.Error())
	}
	if err := vm.Set(string(authorizer.ExpressionVarRequest), params.Request); err != nil {
		return false, fmt.Errorf("authorizer: failed to set request: %v", err.Error())
	}
	if err := vm.Set(string(authorizer.ExpressionVarUser), params.User); err != nil {
		return false, fmt.Errorf("authorizer: failed to set user: %v", err.Error())
	}
	if err := vm.Set(string(authorizer.ExpressionVarIsStream), params.IsStream); err != nil {
		return false, fmt.Errorf("authorizer: failed to set is_stream: %v", err.Error())
	}
	if err := vm.Set(string(authorizer.ExpressionVarMethod), method); err != nil {
		return false, fmt.Errorf("authorizer: failed to set method: %v", err.Error())
	}
	for _, program := range programs {
		v, err := vm.RunProgram(program)
		if err != nil {
			return false, fmt.Errorf("authorizer: failed to run expression: %v", err.Error())
		}
		if v.ToBoolean() {
			return true, nil
		}
	}
	return false, nil
}

func (j *JavascriptAuthorizer) getMethodPrograms(rules *authorize.RuleSet) ([]*goja.Program, error) {
	var (
		programs []*goja.Program
		err      error
	)
	for _, rule := range rules.Rules {
		program, ok := j.cachedPrograms.Load(rule.Expression)
		if !ok {
			program, err = goja.Compile(rule.Expression, rule.Expression, true)
			if err != nil {
				return nil, fmt.Errorf("authorizer: failed to compile expression: %v", err.Error())
			}
			j.cachedPrograms.Store(rule.Expression, program)
		}
		programs = append(programs, program.(*goja.Program))
	}
	return programs, nil
}
