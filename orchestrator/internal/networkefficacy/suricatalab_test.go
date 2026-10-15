package networkefficacy

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This file runs a REAL Suricata binary (via Docker) against a
// synthetic pcap carrying a known signature, to prove
// RealSuricataProvider surfaces evidence Suricata's own detection
// engine genuinely produced -- not a hand-built fixture. It requires
// docker; tests here skip gracefully when it is unavailable.

const suricataTestTimestampEpoch = 1700000000 // 2023-11-14T22:13:20Z

// be16/be32 write big-endian network byte order integers --
// Ethernet/IP/TCP headers are always big-endian ("network order").
func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

// le16/le32 write little-endian integers -- the pcap file format's own
// header fields are little-endian regardless of the captured packets'
// byte order.
func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

// writeTestPcap hand-builds a minimal valid pcap file (global header +
// one Ethernet/IPv4/TCP packet carrying payload) at path. Checksums
// are left zero -- the test invokes suricata with -k none, which
// skips checksum validation, the standard approach for synthetic test
// pcaps. tsSec becomes the packet's capture timestamp, which Suricata
// uses verbatim as the resulting alert's own timestamp field.
func writeTestPcap(t *testing.T, path string, payload []byte, tsSec uint32) {
	t.Helper()

	eth := append([]byte{}, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02) // dst mac
	eth = append(eth, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01)       // src mac
	eth = append(eth, be16(0x0800)...)                          // ethertype = IPv4

	tcp := append([]byte{}, be16(12345)...) // src port
	tcp = append(tcp, be16(80)...)          // dst port
	tcp = append(tcp, be32(1000)...)        // seq
	tcp = append(tcp, be32(0)...)           // ack
	tcp = append(tcp, byte(5<<4), 0x18)     // data offset=5 words, flags=PSH|ACK
	tcp = append(tcp, be16(65535)...)       // window
	tcp = append(tcp, be16(0)...)           // checksum (unchecked, -k none)
	tcp = append(tcp, be16(0)...)           // urgent ptr
	tcp = append(tcp, payload...)

	ipTotalLen := 20 + len(tcp)
	ip := append([]byte{}, 0x45) // version=4, IHL=5
	ip = append(ip, 0)           // DSCP/ECN
	ip = append(ip, be16(uint16(ipTotalLen))...)
	ip = append(ip, be16(1)...) // identification
	ip = append(ip, be16(0)...) // flags/frag offset
	ip = append(ip, 64)         // TTL
	ip = append(ip, 6)          // protocol = TCP
	ip = append(ip, be16(0)...) // header checksum (unchecked, -k none)
	ip = append(ip, 10, 0, 0, 1)
	ip = append(ip, 10, 0, 0, 2)

	packet := append(eth, ip...)
	packet = append(packet, tcp...)

	var out []byte
	out = append(out, le32(0xa1b2c3d4)...) // magic
	out = append(out, le16(2)...)          // version major
	out = append(out, le16(4)...)          // version minor
	out = append(out, le32(0)...)          // thiszone
	out = append(out, le32(0)...)          // sigfigs
	out = append(out, le32(65535)...)      // snaplen
	out = append(out, le32(1)...)          // network = ethernet

	out = append(out, le32(tsSec)...)
	out = append(out, le32(0)...) // ts_usec
	out = append(out, le32(uint32(len(packet)))...)
	out = append(out, le32(uint32(len(packet)))...)
	out = append(out, packet...)

	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write test pcap: %v", err)
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available -- skipping real Suricata lab test")
	}
}

// runSuricataAgainstPcap runs the real jasonish/suricata:latest image
// against a synthetic pcap carrying a known signature, producing a
// genuine eve.json in outputDir. Returns the eve.json path.
func runSuricataAgainstPcap(t *testing.T, tsSec uint32) string {
	t.Helper()
	requireDocker(t)

	dir := t.TempDir()
	pcapDir, rulesDir, outputDir := filepath.Join(dir, "pcap"), filepath.Join(dir, "rules"), filepath.Join(dir, "output")
	for _, d := range []string{pcapDir, rulesDir, outputDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	writeTestPcap(t, filepath.Join(pcapDir, "test.pcap"), []byte("BAS-TEST-SIGNATURE-ALPHA"), tsSec)
	rule := `alert tcp any any -> any any (msg:"BAS lab test signature"; content:"BAS-TEST-SIGNATURE-ALPHA"; sid:1000001; rev:1; classtype:misc-activity;)` + "\n"
	if err := os.WriteFile(filepath.Join(rulesDir, "bastest.rules"), []byte(rule), 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"-v", pcapDir+":/pcap",
		"-v", rulesDir+":/myrules",
		"-v", outputDir+":/output",
		"jasonish/suricata:latest",
		"suricata", "-r", "/pcap/test.pcap", "-l", "/output", "-k", "none", "-S", "/myrules/bastest.rules",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run suricata: %v\n%s", err, out)
	}

	return filepath.Join(outputDir, "eve.json")
}

// TestRealSuricataProvider_LiveEveLog_GenuineAlertSurfaced is the
// regression test closing the master spec's Phase 4 exit criterion:
// at least one real-or-lab-backed IDS/IPS provider integrated
// end-to-end. The alert text asserted below is Suricata's own
// detection-engine output, never something this test injects.
func TestRealSuricataProvider_LiveEveLog_GenuineAlertSurfaced(t *testing.T) {
	evePath := runSuricataAgainstPcap(t, suricataTestTimestampEpoch)

	provider := NewRealSuricataProvider(evePath)
	flow := Flow{SourceCIDR: "10.0.0.0/24", DestCIDR: "10.0.0.0/24", Port: 80, Protocol: "tcp"}
	ts := time.Unix(int64(suricataTestTimestampEpoch), 0).UTC()
	window := TimeWindow{Start: ts.Add(-time.Minute), End: ts.Add(time.Minute)}

	evidence, err := provider.IDSEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("IDSEvidenceFor: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("got %d evidence records, want 1: %+v", len(evidence), evidence)
	}
	if evidence[0].AlertName != "BAS lab test signature" {
		t.Errorf("AlertName = %q, want %q -- must be Suricata's own genuine alert text", evidence[0].AlertName, "BAS lab test signature")
	}
	if evidence[0].SourceIP != "10.0.0.1" || evidence[0].DestIP != "10.0.0.2" || evidence[0].Port != 80 {
		t.Errorf("unexpected flow fields: %+v", evidence[0])
	}
	if evidence[0].Source != SourceLive {
		t.Errorf("Source = %q, want %q -- live-lab evidence must be tagged distinctly from a recorded fixture", evidence[0].Source, SourceLive)
	}
}

// TestRealSuricataProvider_OutsideWindow_NotReturned proves the
// provider still filters live evidence by time window and flow, not
// just returning everything the log contains.
func TestRealSuricataProvider_OutsideWindow_NotReturned(t *testing.T) {
	evePath := runSuricataAgainstPcap(t, suricataTestTimestampEpoch)

	provider := NewRealSuricataProvider(evePath)
	flow := Flow{SourceCIDR: "10.0.0.0/24", DestCIDR: "10.0.0.0/24", Port: 80, Protocol: "tcp"}
	farFuture := time.Unix(int64(suricataTestTimestampEpoch), 0).UTC().Add(24 * time.Hour)
	window := TimeWindow{Start: farFuture, End: farFuture.Add(time.Hour)}

	evidence, err := provider.IDSEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("IDSEvidenceFor: %v", err)
	}
	if len(evidence) != 0 {
		t.Fatalf("got %d evidence records, want 0 -- the alert's real timestamp falls outside the requested window", len(evidence))
	}
}

// TestRealSuricataProvider_MissingFile_ReturnsError proves a genuine
// read failure is reported as an error, not silently treated as "no
// alerts occurred."
func TestRealSuricataProvider_MissingFile_ReturnsError(t *testing.T) {
	provider := NewRealSuricataProvider(filepath.Join(t.TempDir(), "does-not-exist.json"))
	_, err := provider.IDSEvidenceFor(Flow{}, TimeWindow{})
	if err == nil {
		t.Fatal("want an error when the live eve log file does not exist, not a silently empty result")
	}
}
