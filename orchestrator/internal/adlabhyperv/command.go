package adlabhyperv

import "context"

// CommandKind is the kind of host operation the Commander performs.
type CommandKind string

const (
	CmdProvision   CommandKind = "provision"
	CmdProbe       CommandKind = "probe"
	CmdExecuteCase CommandKind = "execute_case"
	CmdTeardown    CommandKind = "teardown"
)

// Command is one host operation. Args carries kind-specific parameters
// (topology name, switch, target id, probe check, case name).
type Command struct {
	Kind CommandKind
	Args map[string]string
}

// Output is the structured result the adapter interprets. Which fields are
// meaningful depends on Command.Kind: provision -> OK, TargetID; probe ->
// Passed, Determinate; execute_case -> PostconditionObserved, Complete;
// teardown -> OK. Detail is diagnostic text for any kind.
type Output struct {
	OK                    bool
	TargetID              string
	Passed                bool
	Determinate           bool
	PostconditionObserved bool
	Complete              bool
	Detail                string
}

// Commander is the ONLY seam to real infrastructure. Faked in tests; the real
// Hyper-V implementation is lab-gated and lives in a future file.
type Commander interface {
	Run(ctx context.Context, cmd Command) (Output, error)
}
