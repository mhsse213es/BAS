// Command segprobe runs a segmentation scenario against the seg-lab and prints
// the verdict for every probe in every run. It reports; it does not decide a
// pass or fail for the whole pack. That is a reporting question for Phase 2.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/audspect/bas/internal/segprobe"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: segprobe run --scenario FILE [--runs N] [--compose FILE]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	scenarioPath := fs.String("scenario", "", "scenario YAML file")
	runs := fs.Int("runs", 3, "number of repeated runs")
	compose := fs.String("compose", "lab/segmentation/docker-compose.yml", "compose file for the seg-lab")
	_ = fs.Parse(os.Args[2:])

	if *scenarioPath == "" {
		fmt.Fprintln(os.Stderr, "--scenario is required")
		os.Exit(2)
	}
	data, err := os.ReadFile(*scenarioPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s, err := segprobe.LoadScenario(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	p := segprobe.NewDockerProvider(*compose)
	results, stable, err := segprobe.RunRepeated(context.Background(), p, s, *runs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "RUN\tPROBE\tSRC→DST\tEXPECT\tVERDICT\tREASON")
	for _, r := range results {
		for _, o := range r.Outcomes {
			fmt.Fprintf(w, "%d\t%s\t%s→%s:%d\t%s\t%s\t%s\n",
				r.RunIndex, o.Spec.ID, o.Spec.Src, o.Spec.Dst, o.Spec.DstPort,
				o.Spec.Expect, o.Verdict, o.Reason)
		}
	}
	_ = w.Flush()
	fmt.Printf("\nscenario=%s runs=%d stable=%v\n", s.ID, *runs, stable)
}
