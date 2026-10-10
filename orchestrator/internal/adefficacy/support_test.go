package adefficacy

import (
	"context"

	"github.com/audspect/bas/internal/controlval"
)

type fakeSource struct {
	dec ControlDecision
	err error
}

func (f fakeSource) Decision(context.Context, controlval.CorrelationKey) (ControlDecision, error) {
	return f.dec, f.err
}
