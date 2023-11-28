package cel

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/mitchellh/mapstructure"

	"github.com/autom8ter/protoc-gen-authorize/authorizer"
	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
)

// CelAuthorizer is a javascript vm that uses javascript expressions to authorize grpc requests
type CelAuthorizer struct {
	rules          map[string]*authorize.RuleSet
	cachedPrograms sync.Map
}

// NewCelAuthorizer returns a new CelAuthorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewCelAuthorizer(rules map[string]*authorize.RuleSet) (*CelAuthorizer, error) {
	a := &CelAuthorizer{
		rules:          rules,
		cachedPrograms: sync.Map{},
	}
	return a, nil
}

// AuthorizeMethod authorizes a gRPC method the RuleExecutionParams and returns a boolean representing whether the
// request is authorized or not.
func (a *CelAuthorizer) AuthorizeMethod(ctx context.Context, method string, params *authorizer.RuleExecutionParams) (bool, error) {
	rules, ok := a.rules[method]
	if !ok {
		return false, nil
	}
	programs, err := a.getMethodPrograms(rules)
	if err != nil {
		return false, err
	}

	var (
		metaMap = map[string]string{}
		request = map[string]interface{}{}
		user    = map[string]interface{}{}
	)
	for k, v := range params.Metadata {
		metaMap[k] = strings.Join(v, ",")
	}
	if err := mapstructure.Decode(params.Request, &request); err != nil {
		return false, fmt.Errorf("authorizer: failed to decode request: %v", err.Error())
	}
	if err := mapstructure.Decode(params.User, &user); err != nil {
		return false, fmt.Errorf("authorizer: failed to decode user: %v", err.Error())
	}

	for _, program := range programs {
		v, _, err := program.Eval(map[string]interface{}{
			string(authorizer.ExpressionVarMetadata): metaMap,
			string(authorizer.ExpressionVarRequest):  request,
			string(authorizer.ExpressionVarUser):     user,
			string(authorizer.ExpressionVarIsStream): params.IsStream,
		})
		if err != nil {
			return false, fmt.Errorf("authorizer: failed to run expression: %v", err.Error())
		}
		pass, ok := v.Value().(bool)
		if !ok {
			return false, fmt.Errorf("authorizer: expression did not return a boolean")
		}
		if pass {
			return true, nil
		}
	}
	return false, nil
}

func (j *CelAuthorizer) getMethodPrograms(rules *authorize.RuleSet) ([]cel.Program, error) {
	var programs []cel.Program
	for _, rule := range rules.Rules {
		program, ok := j.cachedPrograms.Load(rule.Expression)
		if !ok {
			vm, err := cel.NewEnv(
				cel.Variable(string(authorizer.ExpressionVarMetadata), cel.MapType(cel.StringType, cel.StringType)),
				cel.Variable(string(authorizer.ExpressionVarRequest), cel.MapType(cel.StringType, cel.DynType)),
				cel.Variable(string(authorizer.ExpressionVarUser), cel.MapType(cel.StringType, cel.DynType)),
				cel.Variable(string(authorizer.ExpressionVarIsStream), cel.BoolType),
				cel.Macros(cel.StandardMacros...),
			)
			if err != nil {
				return nil, fmt.Errorf("authorizer: failed to create cel env: %v", err.Error())
			}
			parsed, issues := vm.Parse(rule.Expression)
			if issues != nil && issues.Err() != nil {
				return nil, fmt.Errorf("authorizer: failed to parse expression: %v", issues.Err().Error())
			}
			program, err = vm.Program(parsed)
			if err != nil {
				return nil, fmt.Errorf("authorizer: failed to compile expression: %v", err.Error())
			}
			j.cachedPrograms.Store(rule.Expression, program)
		}
		programs = append(programs, program.(cel.Program))
	}
	return programs, nil
}
