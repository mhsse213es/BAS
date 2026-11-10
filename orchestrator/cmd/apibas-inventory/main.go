// Command apibas-inventory imports an OpenAPI 3 document and prints the endpoint inventory API BAS would test.
//
// It reads local files only. It never contacts the servers the specification names. The classes it prints are candidates for
// testing chosen from the shape of the specification; they are not findings.
//
//	apibas-inventory -spec openapi.yaml [-observed routes.txt] [-json]
//
// The observed file has one route per line, "METHOD /path", for example from a gateway log or a route table. With it the command
// also reports the gap between the specification and the routes seen in use.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/audspect/bas/internal/apibas/openapi"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "apibas-inventory:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("apibas-inventory", flag.ContinueOnError)
	specPath := fs.String("spec", "", "OpenAPI 3.x or Swagger 2.0 document (JSON or YAML)")
	observedPath := fs.String("observed", "", "optional file of observed routes, one METHOD /path per line")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specPath == "" {
		return fmt.Errorf("-spec is required")
	}
	data, err := readLimited(*specPath, openapi.MaxDocumentBytes)
	if err != nil {
		return err
	}
	inv, err := openapi.Import(data)
	if err != nil {
		return err
	}
	var drift *openapi.Drift
	if *observedPath != "" {
		obs, err := readObserved(*observedPath)
		if err != nil {
			return err
		}
		d := inv.Diff(obs)
		drift = &d
	}
	if *asJSON {
		return writeJSON(out, inv, drift)
	}
	writeText(out, inv, drift)
	return nil
}

// readLimited reads a file but refuses to read more than max+1 bytes, so a huge file is not loaded whole.
func readLimited(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func readObserved(path string) ([]openapi.Observed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []openapi.Observed
	sc := bufio.NewScanner(io.LimitReader(f, 16<<20))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "/") {
			return nil, fmt.Errorf("%s line %d: want \"METHOD /path\"", path, n)
		}
		out = append(out, openapi.Observed{Method: fields[0], Path: fields[1]})
	}
	return out, sc.Err()
}

func writeText(w io.Writer, inv *openapi.Inventory, drift *openapi.Drift) {
	fmt.Fprintf(w, "%s %s (OpenAPI %s): %d operations\n", inv.Title, inv.Version, inv.OpenAPIVersion, len(inv.Operations))
	fmt.Fprintln(w, "Classes below are candidates for testing from the shape of the specification. They are not findings.")
	fmt.Fprintln(w)
	for _, ci := range openapi.Classes {
		ops := inv.ByClass(ci.Class)
		if len(ops) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s [%s] %d\n  %s\n", ci.Class, ci.Category, len(ops), ci.Meaning)
		for _, o := range ops {
			fmt.Fprintf(w, "    %s\n", o.Key())
		}
	}
	if scope := inv.SuggestedScope(); len(scope) > 0 {
		fmt.Fprintf(w, "\nSuggested allowed path prefixes (a person must confirm them): %s\n", strings.Join(scope, " "))
	}
	if len(inv.Warnings) > 0 {
		fmt.Fprintln(w, "\nWarnings:")
		for _, x := range inv.Warnings {
			fmt.Fprintf(w, "  %s\n", x)
		}
	}
	if drift != nil {
		fmt.Fprintf(w, "\nDrift against observed routes: %d undocumented, %d specified but not seen, %d deprecated in use\n",
			len(drift.Undocumented), len(drift.Unserved), len(drift.DeprecatedInUse))
		for _, u := range drift.Undocumented {
			fmt.Fprintf(w, "  undocumented: %s %s\n", u.Method, u.Path)
		}
		for _, o := range drift.DeprecatedInUse {
			fmt.Fprintf(w, "  deprecated in use: %s\n", o.Key())
		}
	}
}

func writeJSON(w io.Writer, inv *openapi.Inventory, drift *openapi.Drift) error {
	type op struct {
		Method, Path, OperationID string
		Auth                      openapi.AuthMode
		Deprecated                bool
		Classes                   []openapi.Class
	}
	rep := struct {
		Title, Version, OpenAPIVersion string
		Operations                     []op
		SuggestedScope                 []string
		Warnings                       []string
		Undocumented                   []openapi.Observed `json:",omitempty"`
	}{Title: inv.Title, Version: inv.Version, OpenAPIVersion: inv.OpenAPIVersion, SuggestedScope: inv.SuggestedScope(), Warnings: inv.Warnings}
	for _, o := range inv.Operations {
		rep.Operations = append(rep.Operations, op{o.Method, o.Path, o.OperationID, o.Auth, o.Deprecated, o.Classes})
	}
	if drift != nil {
		rep.Undocumented = drift.Undocumented
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
