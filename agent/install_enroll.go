package main

import (
	"context"
	"os"
)

// enrollAtInstall performs the first enrolment during --install when the operator supplied a
// single-use enrolment token (audit F-03). Doing it here means the token is used once, by the
// installing process, and never has to be stored for the service to find later: the service starts
// already enrolled. enrollPort is the enrolment listener's host port if it was remapped ("" = default).
// A refused token returns an error so the install fails visibly instead of producing an agent that
// silently cannot enrol. An identity that is already enrolled is left untouched.
func enrollAtInstall(ctx context.Context, cfg Config, enrollPort, agentID string) error {
	if enrollPort != "" {
		prev, had := os.LookupEnv("BAS_ENROLL_PORT")
		os.Setenv("BAS_ENROLL_PORT", enrollPort)
		defer func() {
			if had {
				os.Setenv("BAS_ENROLL_PORT", prev)
			} else {
				os.Unsetenv("BAS_ENROLL_PORT")
			}
		}()
	}
	if _, err := ensureCertificate(ctx, cfg, agentID); err != nil {
		return classifyEnrollError(err)
	}
	return nil
}
