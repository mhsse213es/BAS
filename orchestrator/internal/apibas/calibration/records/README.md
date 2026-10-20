# Timing calibration records

Each file is one calibration version for one timing scenario: `<SCENARIO-ID>.v<N>.json`.

- Records are write-once. A recalibration writes the next version and names the version
  it supersedes. Earlier versions are never edited or deleted.
- A scenario declares `calibration.version`, `baseline_ms`, `tolerance` and `attack_max_ms`
  in its catalog file. Its declared values must match the record field for field, or the
  timing grade is ERROR (`CALIBRATION_MISMATCH`).
- Recalibrate with `apibas-runner -calibrate ...`. The command measures the baseline and
  prints the record and the catalog values to change. Nothing is widened automatically.
