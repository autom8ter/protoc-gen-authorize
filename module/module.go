package module

import (
	"bytes"
	"fmt"
	"text/template"

	pgs "github.com/lyft/protoc-gen-star"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"

	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
)

// Module is the protoc-gen-authorizer module
// implements the protoc-gen-star module interface
type module struct {
	*pgs.ModuleBase
	pgsgo.Context
}

func New() pgs.Module {
	return &module{ModuleBase: &pgs.ModuleBase{}}
}

func (m *module) Name() string {
	return "authorizer"
}

func (m *module) InitContext(c pgs.BuildContext) {
	m.ModuleBase.InitContext(c)
	m.Context = pgsgo.InitContext(c.Parameters())
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
	t, err := template.New("authorizer").Parse(tmpl)
	if err != nil {
		m.AddError(err.Error())
		return
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

var tmpl = `
package {{ .Package }}

import (
	"github.com/autom8ter/protoc-gen-authorize/authorizer"
	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
)


func NewJavascriptAuthorizer() (*authorizer.JavascriptAuthorizer, error) {
	return authorizer.NewJavascriptAuthorizer(map[string]*authorize.RuleSet{
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
