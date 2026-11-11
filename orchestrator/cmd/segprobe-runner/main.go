// Command segprobe-runner performs one TCP connection attempt and prints the
// result as one JSON object. It is a static binary placed in each lab probe
// container; the orchestrator-side DockerProvider parses its output.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// probeTCP dials addr once and returns the outcome name used by segprobe.
func probeTCP(addr string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		_ = conn.Close()
		return "connected"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	return "destination_unavailable"
}

type output struct {
	Outcome string `json:"outcome"`
	Start   string `json:"start"`
	End     string `json:"end"`
}

func main() {
	dst := flag.String("dst", "", "destination IPv4 address")
	port := flag.Int("port", 0, "destination TCP port")
	proto := flag.String("proto", "tcp", "protocol (only tcp is supported)")
	timeout := flag.Duration("timeout", 3*time.Second, "connection deadline")
	flag.Parse()

	if *dst == "" || *port <= 0 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "usage: segprobe-runner --dst IP --port N [--proto tcp] [--timeout 3s]")
		os.Exit(2)
	}
	if *proto != "tcp" {
		fmt.Fprintf(os.Stderr, "unsupported protocol %q\n", *proto)
		os.Exit(2)
	}

	start := time.Now().UTC()
	outcome := probeTCP(net.JoinHostPort(*dst, fmt.Sprint(*port)), *timeout)
	end := time.Now().UTC()

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(output{
		Outcome: outcome,
		Start:   start.Format(time.RFC3339Nano),
		End:     end.Format(time.RFC3339Nano),
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
