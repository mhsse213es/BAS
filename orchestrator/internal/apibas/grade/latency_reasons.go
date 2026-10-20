package grade

// Reasons for timing evidence that cannot be graded as a pass or a failure. A
// noisy or inconsistent measurement is ERROR, never a security pass.
const (
	ReasonNoisyMeasurement   = "NOISY_MEASUREMENT"
	ReasonInconsistentRounds = "INCONSISTENT_ACROSS_ROUNDS"
)
