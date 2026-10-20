package grade

// Reasons for timing evidence that cannot be graded as a pass or a failure. Each
// reason names the validity check that stopped grading. None of them is a security
// pass.
const (
	// ERROR: a measurement is outside the band where the threshold is valid.
	ReasonEnvironmentMismatch      = "ENVIRONMENT_MISMATCH"       // baseline outside the calibrated band
	ReasonAttackMeasurementInvalid = "ATTACK_MEASUREMENT_INVALID" // attack outside the valid measurement band
	ReasonCalibrationMissing       = "CALIBRATION_MISSING"        // no calibration record for the declared version
	ReasonCalibrationMismatch      = "CALIBRATION_MISMATCH"       // declared thresholds differ from the record

	// INCONCLUSIVE (reported as SKIPPED): the measurement is too weak to decide.
	ReasonExcessiveVariance   = "EXCESSIVE_VARIANCE"
	ReasonInsufficientSamples = "INSUFFICIENT_SAMPLES"
	ReasonBelowEffectSize     = "BELOW_EFFECT_SIZE"
	ReasonInconsistentRounds  = "INCONSISTENT_ACROSS_ROUNDS"
)
