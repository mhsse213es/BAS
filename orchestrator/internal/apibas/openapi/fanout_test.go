package openapi

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A schema that fans out through shared references must not make the import exponential. Twelve properties per level, eight
// levels deep, would be about 12^8 nodes without a budget.
func TestSchemaFanOutIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("openapi: 3.0.0\npaths:\n  /a:\n    get:\n      responses:\n        \"200\":\n          description: ok\n          content:\n            application/json:\n              schema: {$ref: \"#/components/schemas/L0\"}\ncomponents:\n  schemas:\n")
	for level := 0; level < 8; level++ {
		fmt.Fprintf(&b, "    L%d:\n      type: object\n      properties:\n", level)
		for i := 0; i < 12; i++ {
			fmt.Fprintf(&b, "        p%d: {$ref: \"#/components/schemas/L%d\"}\n", i, level+1)
		}
	}
	b.WriteString("    L8: {type: object, properties: {leaf: {type: string}}}\n")
	start := time.Now()
	inv, err := Import([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("the import took %v; the fan-out is not bounded", time.Since(start))
	}
	if !strings.Contains(strings.Join(inv.Warnings, "|"), "too large") {
		t.Errorf("the fan-out was not reported: %v", inv.Warnings)
	}
}
