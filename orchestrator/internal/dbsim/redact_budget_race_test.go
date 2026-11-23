//go:build race

package dbsim

import "time"

// redactBudget is how long redact may take on the adversarial inputs. The race detector slows regex-heavy code by roughly
// 18x (about 0.2s becomes about 4s), so the budget is wider under -race. Catastrophic backtracking on these 100k-character
// inputs would take minutes, so it is still caught.
const redactBudget = 20 * time.Second
