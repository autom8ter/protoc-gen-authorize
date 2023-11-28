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

// JavascriptAuthorizer is a javascript vm that uses javascript expressions to authorize grpc requests
type JavascriptAuthorizer struct {
	rules          map[string]*authorize.RuleSet
	cachedPrograms sync.Map
	vms            chan *goja.Runtime
}

// NewJavascriptAuthorizer returns a new JavascriptAuthorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewJavascriptAuthorizer(rules map[string]*authorize.RuleSet) (*JavascriptAuthorizer, error) {
	a := &JavascriptAuthorizer{
		rules:          rules,
		cachedPrograms: sync.Map{},
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
func (a *JavascriptAuthorizer) AuthorizeMethod(ctx context.Context, method string, params *authorizer.RuleExecutionParams) (bool, error) {
	rules, ok := a.rules[method]
	if !ok {
		return false, nil
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
