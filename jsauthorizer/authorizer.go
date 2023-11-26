package jsauthorizer

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/dop251/goja"

	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"

	"github.com/autom8ter/protoc-gen-authorize/authorizer"
)

// JavascriptGlobal is a global variable injected into a javascript function (triggers/authorizers/etc)
type JavascriptGlobal string

const (
	// JavascriptGlobalRequest is the request object
	JavascriptGlobalRequest JavascriptGlobal = "request"
	// JavascriptGlobalMetadata is the metadata object
	JavascriptGlobalMetadata JavascriptGlobal = "metadata"
	// JavascriptGlobalUser is the user object
	JavascriptGlobalUser JavascriptGlobal = "user"
)

type opts struct {
	extractor UserExtractor
	overrides map[string]any
}

// Opt is an option for configuring the authorizer
type Opt func(*opts)

// WithUserExtractor sets the user extractor for the authorizer
func WithUserExtractor(extractor UserExtractor) Opt {
	return func(o *opts) {
		o.extractor = extractor
	}
}

// WithBuiltins adds builtins to the javascript runtime
func WithBuiltins(overrides map[string]any) Opt {
	return func(o *opts) {
		o.overrides = overrides
	}
}

// UserExtractor is a function that extracts a user from a context
type UserExtractor func(ctx context.Context) (any, error)

// Authorizer is a javascript authorizer
type Authorizer struct {
	overrides      map[string]any
	userExtractor  UserExtractor
	cachedPrograms map[string][]*goja.Program
	mu             sync.RWMutex
	vms            chan *goja.Runtime
}

// New returns a new Authorizer
func New(options ...Opt) (*Authorizer, error) {
	o := &opts{}
	for _, opt := range options {
		opt(o)
	}
	if o.extractor == nil {
		o.extractor = func(ctx context.Context) (any, error) {
			return nil, nil
		}
	}
	if o.overrides == nil {
		o.overrides = map[string]any{}
	}
	a := &Authorizer{
		overrides:      o.overrides,
		userExtractor:  o.extractor,
		cachedPrograms: map[string][]*goja.Program{},
		mu:             sync.RWMutex{},
		vms:            make(chan *goja.Runtime, 100),
	}
	{
		runtime := goja.New()
		for k, v := range a.overrides {
			if err := runtime.Set(k, v); err != nil {
				return nil, fmt.Errorf("authorizer: failed to set override: %v", err.Error())
			}
		}
		a.vms <- runtime
	}
	go func() {
		for {
			runtime := goja.New()
			for k, v := range a.overrides {
				runtime.Set(k, v)
			}
			a.vms <- runtime
		}
	}()
	return a, nil
}

func (a *Authorizer) ExecuteRule(ctx context.Context, rule *authorize.Rule, params *authorizer.RuleExecutionParams) (bool, error) {
	var (
		program *goja.Program
		err     error
	)
	a.mu.RLock()
	programs, ok := a.cachedPrograms[rule.Expression]
	if !ok {
		a.mu.RUnlock()
		a.mu.Lock()
		defer a.mu.Unlock()
		program, err = goja.Compile(rule.Expression, rule.Expression, true)
		if err != nil {
			return false, fmt.Errorf("authorizer: failed to compile expression: %v", err.Error())
		}
		a.cachedPrograms[rule.Expression] = []*goja.Program{program}
	} else {
		program = programs[0]
		a.mu.RUnlock()
	}
	vm := <-a.vms
	var (
		metaMap = map[string]string{}
		//userMap    = map[string]any{}
		//requestMap = map[string]any{}
	)
	//if user != nil {
	//	if err := mapstructure.WeakDecode(user, &userMap); err != nil {
	//		return nil, err
	//	}
	//}
	//if request != nil {
	//	if err := mapstructure.WeakDecode(request, &requestMap); err != nil {
	//		return err
	//	}
	//}
	for k, v := range params.Metadata {
		metaMap[k] = strings.Join(v, ",")
	}
	if err := vm.Set(string(JavascriptGlobalMetadata), metaMap); err != nil {
		return false, fmt.Errorf("authorizer: failed to set metadata: %v", err.Error())
	}
	if err := vm.Set(string(JavascriptGlobalRequest), params.Request); err != nil {
		return false, fmt.Errorf("authorizer: failed to set request: %v", err.Error())
	}
	if err := vm.Set(string(JavascriptGlobalUser), params.User); err != nil {
		return false, fmt.Errorf("authorizer: failed to set user: %v", err.Error())
	}
	v, err := vm.RunProgram(program)
	if err != nil {
		return false, fmt.Errorf("authorizer: failed to run expression: %v", err.Error())
	}
	return v.ToBoolean(), nil
}

// ExtractUser extracts a user from a context
func (a *Authorizer) ExtractUser(ctx context.Context) (any, error) {
	return a.userExtractor(ctx)
}
