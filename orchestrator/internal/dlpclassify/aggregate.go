package dlpclassify

// SampleResult pairs one sample's verdict with the observed class its
// evidence actually carried -- a bare DLPCLSVerdict never carries
// ObservedClass (only ClassificationEvidence does), so the caller who
// ran VerifyClassificationSample passes both along here, rather than
// AggregateCorpusMetrics trying to recover ObservedClass by parsing
// Verdict.Reason.
type SampleResult struct {
	SampleID      string           `json:"sampleId"`
	Verdict       DLPCLSVerdict    `json:"verdict"`
	ObservedClass SensitivityClass `json:"observedClass,omitempty"`
}

type CorpusMetrics struct {
	TotalSamples      int                                           `json:"totalSamples"`
	Evaluated         int                                           `json:"evaluated"` // TP+FP+FN+TN+Misclassified
	Inconclusive      int                                           `json:"inconclusive"`
	Unsupported       int                                           `json:"unsupported"`
	NotTested         int                                           `json:"notTested"`
	TruePositives     int                                           `json:"truePositives"`
	FalsePositives    int                                           `json:"falsePositives"`
	FalseNegatives    int                                           `json:"falseNegatives"`
	TrueNegatives     int                                           `json:"trueNegatives"`
	Misclassified     int                                           `json:"misclassified"`
	Precision         Rate                                          `json:"precision"`         // TP / (TP+FP)
	Recall            Rate                                          `json:"recall"`            // TP / (TP+FN)
	FalseNegativeRate Rate                                          `json:"falseNegativeRate"` // FN / (FN+TP)
	FalsePositiveRate Rate                                          `json:"falsePositiveRate"` // FP / (FP+TN)
	ConfusionMatrix   map[SensitivityClass]map[SensitivityClass]int `json:"confusionMatrix"`   // [intended][observed] -> count, Evaluated samples only
}

// AggregateCorpusMetrics rolls per-sample results into corpus-level
// metrics. Only Evaluated outcomes enter Precision/Recall/the
// confusion matrix's denominators; Inconclusive/Unsupported/NotTested
// are always counted and reported, never silently dropped.
func AggregateCorpusMetrics(samples []SampleResult, truths map[string]GroundTruth) CorpusMetrics {
	m := CorpusMetrics{
		TotalSamples:    len(samples),
		ConfusionMatrix: make(map[SensitivityClass]map[SensitivityClass]int),
	}

	for _, s := range samples {
		switch s.Verdict.Outcome {
		case OutcomeNotTested:
			m.NotTested++
			continue
		case OutcomeUnsupported:
			m.Unsupported++
			continue
		case OutcomeInconclusive:
			m.Inconclusive++
			continue
		}
		if !s.Verdict.Outcome.evaluated() {
			continue
		}
		m.Evaluated++

		observed := s.ObservedClass
		switch s.Verdict.Outcome {
		case OutcomeTruePositive:
			m.TruePositives++
		case OutcomeFalsePositive:
			m.FalsePositives++
		case OutcomeFalseNegative:
			m.FalseNegatives++
			observed = SensitivityClassNone
		case OutcomeTrueNegative:
			m.TrueNegatives++
			observed = SensitivityClassNone
		case OutcomeMisclassified:
			m.Misclassified++
		}

		intended := truths[s.SampleID].IntendedClass
		if m.ConfusionMatrix[intended] == nil {
			m.ConfusionMatrix[intended] = make(map[SensitivityClass]int)
		}
		m.ConfusionMatrix[intended][observed]++
	}

	m.Precision = rate(float64(m.TruePositives), float64(m.TruePositives+m.FalsePositives))
	m.Recall = rate(float64(m.TruePositives), float64(m.TruePositives+m.FalseNegatives))
	m.FalseNegativeRate = rate(float64(m.FalseNegatives), float64(m.FalseNegatives+m.TruePositives))
	m.FalsePositiveRate = rate(float64(m.FalsePositives), float64(m.FalsePositives+m.TrueNegatives))

	return m
}

// rate computes numerator/denominator, reporting Defined: false rather
// than a misleading 0.0 when denominator is zero.
func rate(numerator, denominator float64) Rate {
	if denominator == 0 {
		return Rate{Defined: false}
	}
	return Rate{Value: numerator / denominator, Defined: true}
}

// CompareChannelVerdicts reports whether two per-channel verdicts for
// the same SampleID agree -- compares only Outcome, never Reason text,
// since two channels both producing e.g. OutcomeTruePositive agree
// regardless of any metadata difference in how they got there.
func CompareChannelVerdicts(a, b DLPCLSVerdict) bool {
	return a.Outcome == b.Outcome
}
