package cveval

import (
	"errors"
	"fmt"
)

var errCVEIDRequired = errors.New("cveval: Result.CVEID must not be empty")

func newInvalidVerdictError(v Verdict) error {
	return fmt.Errorf("cveval: %q is not one of the known Verdict constants", v)
}

func newMissingEvidenceError(v Verdict) error {
	return fmt.Errorf("cveval: verdict %q requires Evidence.Source to be set -- a definite verdict without evidence is not reportable", v)
}

func newMissingEvidenceDetailError(v Verdict) error {
	return fmt.Errorf("cveval: verdict %q requires Evidence.Detail to be set -- never report a definite verdict without saying what evidence supports it", v)
}

func newMissingDetailError(v Verdict) error {
	return fmt.Errorf("cveval: verdict %q requires Result.Detail to explain why", v)
}
