package property

import "github.com/audspect/bas/internal/aleef/model"

type StepKind string

const (
	StepCreate    StepKind = "create"
	StepAuthorize StepKind = "authorize"
	StepExecute   StepKind = "execute"
	StepModify    StepKind = "modify"
	StepReverse   StepKind = "reverse"
	StepRead      StepKind = "read"
)

type WorkflowStep struct {
	Op   string
	Kind StepKind
	Role string
	Body string
}
type Workflow struct {
	Name          string
	Steps         []WorkflowStep
	SuccessValues []string
}
type auth1 struct{ meta }

func (auth1) Applies(model.Operation, model.Model) bool { return false }
func (auth1) Templates(TemplateCtx) []Template          { return nil }

type auth2 struct{ meta }

func (auth2) Applies(model.Operation, model.Model) bool { return false }
func (auth2) Templates(TemplateCtx) []Template          { return nil }

type mc1 struct{ meta }

func (mc1) Applies(model.Operation, model.Model) bool { return false }
func (mc1) Templates(TemplateCtx) []Template          { return nil }

type state1 struct{ meta }

func (state1) Applies(model.Operation, model.Model) bool { return false }
func (state1) Templates(TemplateCtx) []Template          { return nil }

type state2 struct{ meta }

func (state2) Applies(model.Operation, model.Model) bool { return false }
func (state2) Templates(TemplateCtx) []Template          { return nil }
