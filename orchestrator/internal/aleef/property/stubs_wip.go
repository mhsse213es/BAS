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
type role1 struct{ meta }

func (role1) Applies(model.Operation, model.Model) bool { return false }
func (role1) Templates(TemplateCtx) []Template          { return nil }

type role2 struct{ meta }

func (role2) Applies(model.Operation, model.Model) bool { return false }
func (role2) Templates(TemplateCtx) []Template          { return nil }

type auth1 struct{ meta }

func (auth1) Applies(model.Operation, model.Model) bool { return false }
func (auth1) Templates(TemplateCtx) []Template          { return nil }

type auth2 struct{ meta }

func (auth2) Applies(model.Operation, model.Model) bool { return false }
func (auth2) Templates(TemplateCtx) []Template          { return nil }

type mc1 struct{ meta }

func (mc1) Applies(model.Operation, model.Model) bool { return false }
func (mc1) Templates(TemplateCtx) []Template          { return nil }

type idem1 struct{ meta }

func (idem1) Applies(model.Operation, model.Model) bool { return false }
func (idem1) Templates(TemplateCtx) []Template          { return nil }

type idem2 struct{ meta }

func (idem2) Applies(model.Operation, model.Model) bool { return false }
func (idem2) Templates(TemplateCtx) []Template          { return nil }

type state1 struct{ meta }

func (state1) Applies(model.Operation, model.Model) bool { return false }
func (state1) Templates(TemplateCtx) []Template          { return nil }

type state2 struct{ meta }

func (state2) Applies(model.Operation, model.Model) bool { return false }
func (state2) Templates(TemplateCtx) []Template          { return nil }

type race1 struct{ meta }

func (race1) Applies(model.Operation, model.Model) bool { return false }
func (race1) Templates(TemplateCtx) []Template          { return nil }
