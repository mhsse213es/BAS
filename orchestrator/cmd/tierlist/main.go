// Command tierlist prints the product lines a licence tier permits, one per line. The Windows build
// uses it to decide which scenario files to package, so the build and the server read the same
// mapping in internal/license.
//
// Usage: go run ./cmd/tierlist Core
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/audspect/bas/internal/license"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tierlist <Core|Advanced|Enterprise>")
		os.Exit(2)
	}
	products, err := license.TierProducts(license.Tier(os.Args[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	lines := make([]string, 0, len(products))
	for p := range products {
		lines = append(lines, string(p))
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
}
