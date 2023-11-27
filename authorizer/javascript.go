package authorizer

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/dop251/goja"

	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
)

// ExpressionVar is a global variable injected into a javascript authorization expression
type ExpressionVar string

const (
	// ExpressionVarRequest is the request object
	ExpressionVarRequest ExpressionVar = "request"
	// ExpressionVarMetadata is the metadata object
	ExpressionVarMetadata ExpressionVar = "metadata"
	// ExpressionVarUser is the user object
	ExpressionVarUser ExpressionVar = "user"
	// ExpressionVarIsStream is true if the grpc handler is a streaming handler
	ExpressionVarIsStream ExpressionVar = "is_stream"
)

// JavascriptAuthorizer is a javascript vm that uses javascript expressions to authorize grpc requests
type JavascriptAuthorizer struct {
	rules          map[string]*authorize.RuleSet
	cachedPrograms map[string]*goja.Program
	mu             sync.RWMutex
	vms            chan *goja.Runtime
}

// NewJavascriptAuthorizer returns a new JavascriptAuthorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewJavascriptAuthorizer(rules map[string]*authorize.RuleSet) (*JavascriptAuthorizer, error) {
	a := &JavascriptAuthorizer{
		rules:          rules,
		cachedPrograms: map[string]*goja.Program{},
		mu:             sync.RWMutex{},
		vms:            make(chan *goja.Runtime, 10),
	}
	{
		runtime := goja.New()
		a.vms <- runtime
	}
	go func() {
		for {
			runtime := goja.New()
			a.vms <- runtime
		}
	}()
	return a, nil
}

// AuthorizeMethod authorizes a gRPC method the RuleExecutionParams and returns a boolean representing whether the
// request is authorized or not.
func (a *JavascriptAuthorizer) AuthorizeMethod(ctx context.Context, method string, params *RuleExecutionParams) (bool, error) {
	rules, ok := a.rules[method]
	if !ok {
		return true, nil
	}
	programs, err := a.getMethodPrograms(rules)
	if err != nil {
		return false, err
	}
	vm := <-a.vms
	var (
		metaMap = map[string]string{}
	)
	for k, v := range params.Metadata {
		metaMap[k] = strings.Join(v, ",")
	}
	if err := vm.Set(string(ExpressionVarMetadata), metaMap); err != nil {
		return false, fmt.Errorf("authorizer: failed to set metadata: %v", err.Error())
	}
	if err := vm.Set(string(ExpressionVarRequest), params.Request); err != nil {
		return false, fmt.Errorf("authorizer: failed to set request: %v", err.Error())
	}
	if err := vm.Set(string(ExpressionVarUser), params.User); err != nil {
		return false, fmt.Errorf("authorizer: failed to set user: %v", err.Error())
	}
	if err := vm.Set(string(ExpressionVarIsStream), params.IsStream); err != nil {
		return false, fmt.Errorf("authorizer: failed to set is_stream: %v", err.Error())
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
	j.mu.RLock()
	for _, rule := range rules.Rules {
		program, ok := j.cachedPrograms[rule.Expression]
		if !ok {
			j.mu.RUnlock()
			j.mu.Lock()
			program, err = goja.Compile(rule.Expression, rule.Expression, true)
			if err != nil {
				j.mu.Unlock()
				return nil, fmt.Errorf("authorizer: failed to compile expression: %v", err.Error())
			}
			j.cachedPrograms[rule.Expression] = program
			j.mu.Unlock()
			j.mu.RLock()
		}
		programs = append(programs, program)
	}
	j.mu.RUnlock()
	return programs, nil
}
