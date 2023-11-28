package module

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	pgs "github.com/lyft/protoc-gen-star"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"

	"github.com/autom8ter/proto/gen/authorize"
)

// Module is the protoc-gen-authorizer module
// implements the protoc-gen-star module interface
type module struct {
	*pgs.ModuleBase
	pgsgo.Context
	authorizer string
}

func New() pgs.Module {
	return &module{ModuleBase: &pgs.ModuleBase{}}
}

func (m *module) Name() string {
	return "authorize"
}

func (m *module) InitContext(c pgs.BuildContext) {
	m.ModuleBase.InitContext(c)
	m.Context = pgsgo.InitContext(c.Parameters())
	params := c.Parameters()
	m.authorizer = params.Str("authorizer")
	if m.authorizer == "" {
		m.authorizer = "cel"
	}
	m.authorizer = strings.ToLower(m.authorizer)
}

func (m *module) Execute(targets map[string]pgs.File, packages map[string]pgs.Package) []pgs.Artifact {
	for _, f := range targets {
		if f.BuildTarget() {
			m.generate(f)
		}
	}
	return m.Artifacts()
}

func (m *module) generate(f pgs.File) {
	var rules = map[string]*authorize.RuleSet{}
	for _, s := range f.Services() {
		for _, method := range s.Methods() {
			var ruleSet authorize.RuleSet
			ok, err := method.Extension(authorize.E_Rules, &ruleSet)
			if err != nil {
				m.AddError(err.Error())
				continue
			}
			if !ok {
				continue
			}
			// EchoService_Echo_FullMethodName
			name := fmt.Sprintf("%s_%s_FullMethodName", s.Name().UpperCamelCase(), method.Name().UpperCamelCase())
			rules[name] = &ruleSet
		}
	}
	if len(rules) == 0 {
		return
	}
	name := f.InputPath().SetExt(".pb.authorizer.go").String()
	var (
		t   *template.Template
		err error
	)
	switch m.authorizer {
	case "javascript":
		t, err = template.New("authorizer").Parse(javascriptTmpl)
		if err != nil {
			m.AddError(err.Error())
			return
		}
	case "cel":
		t, err = template.New("authorizer").Parse(celTmpl)
	}

	buffer := &bytes.Buffer{}
	if err := t.Execute(buffer, templateData{
		Package: m.Context.PackageName(f).String(),
		Rules:   rules,
	}); err != nil {
		m.AddError(err.Error())
		return
	}
	m.AddGeneratorFile(name, buffer.String())
}

type templateData struct {
	Package string
	Rules   map[string]*authorize.RuleSet
}

var javascriptTmpl = `
package {{ .Package }}

import (
	"github.com/autom8ter/proto/gen/authorize"

	"github.com/autom8ter/protoc-gen-authorize/authorizer/javascript"
)

// NewAuthorizer returns a new javascript authorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewAuthorizer() (*javascript.JavascriptAuthorizer, error) {
	return javascript.NewJavascriptAuthorizer(map[string]*authorize.RuleSet{
	{{- range $key, $value := .Rules }}
	{{$key}}: {
		Rules: []*authorize.Rule{
		{{- range $value.Rules }}
			{
				Expression: "{{ .Expression }}",
			},
		{{- end }}
		},
	},
	{{- end }}
})
}
`

var celTmpl = `
package {{ .Package }}

import (
	"github.com/autom8ter/proto/gen/authorize"

	"github.com/autom8ter/protoc-gen-authorize/authorizer/cel"
)

// NewAuthorizer returns a new javascript authorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewAuthorizer() (*cel.CelAuthorizer, error) {
	return cel.NewCelAuthorizer(map[string]*authorize.RuleSet{
	{{- range $key, $value := .Rules }}
	{{$key}}: {
		Rules: []*authorize.Rule{
		{{- range $value.Rules }}
			{
				Expression: "{{ .Expression }}",
			},
		{{- end }}
		},
	},
	{{- end }}
})
}
`
