package adlabhyperv

import "context"

// fakeCommander is a programmable Commander for tests. Each kind has a default
// happy-path func that override fields replace per test.
type fakeCommander struct {
	provision func(Command) (Output, error)
	probe     func(Command) (Output, error)
	execute   func(Command) (Output, error)
	teardown  func(Command) (Output, error)
	calls     []Command
}

func newFakeCommander() *fakeCommander {
	return &fakeCommander{
		provision: func(Command) (Output, error) { return Output{OK: true, TargetID: "dc-only/run1"}, nil },
		probe:     func(Command) (Output, error) { return Output{Passed: true, Determinate: true}, nil },
		execute:   func(Command) (Output, error) { return Output{PostconditionObserved: true, Complete: true}, nil },
		teardown:  func(Command) (Output, error) { return Output{OK: true}, nil },
	}
}

func (f *fakeCommander) Run(_ context.Context, cmd Command) (Output, error) {
	f.calls = append(f.calls, cmd)
	switch cmd.Kind {
	case CmdProvision:
		return f.provision(cmd)
	case CmdProbe:
		return f.probe(cmd)
	case CmdExecuteCase:
		return f.execute(cmd)
	case CmdTeardown:
		return f.teardown(cmd)
	}
	return Output{}, nil
}
