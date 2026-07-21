package ioc

import "testing"

func TestExtractIndicators_IPv4Public(t *testing.T) {
	text := "beaconing to 45.33.32.156 every 60s"
	got := ExtractIndicators(text)
	if len(got) != 1 {
		t.Fatalf("got %d indicators, want 1: %+v", len(got), got)
	}
	ind := got[0]
	if ind.Type != "ip" || ind.Value != "45.33.32.156" || ind.Confidence != 95 {
		t.Errorf("got %+v", ind)
	}
	if text[ind.OffsetStart:ind.OffsetEnd] != "45.33.32.156" {
		t.Errorf("offsets [%d:%d] = %q, want 45.33.32.156", ind.OffsetStart, ind.OffsetEnd, text[ind.OffsetStart:ind.OffsetEnd])
	}
}

func TestExtractIndicators_IPv4Private_Filtered(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "172.16.4.4", "192.168.1.1", "127.0.0.1", "169.254.1.1"} {
		got := ExtractIndicators("connecting to " + ip)
		if len(got) != 0 {
			t.Errorf("private IP %s was not filtered: %+v", ip, got)
		}
	}
}

func TestExtractIndicators_IPv4InvalidOctet_Rejected(t *testing.T) {
	got := ExtractIndicators("windows build 10.0.19045.1")
	for _, ind := range got {
		if ind.Type == "ip" {
			t.Errorf("version string matched as IP: %+v", ind)
		}
	}
}

func TestExtractIndicators_Domain(t *testing.T) {
	got := ExtractIndicators("resolved evil.Example.COM via DNS")
	if len(got) != 1 || got[0].Type != "domain" || got[0].Value != "evil.example.com" || got[0].Confidence != 80 {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractIndicators_Domain_FileExtensionBlocked(t *testing.T) {
	got := ExtractIndicators("launched svchost.exe and wrote report.json")
	for _, ind := range got {
		if ind.Type == "domain" {
			t.Errorf("filename matched as domain: %+v", ind)
		}
	}
}

func TestExtractIndicators_Domain_ShTLDTradeoff(t *testing.T) {
	// Documented tradeoff: ".sh" is filtered as a shell-script extension, so a
	// legitimate "example.sh" domain is a known, accepted false negative.
	got := ExtractIndicators("curl https://example.sh/x")
	for _, ind := range got {
		if ind.Type == "domain" && ind.Value == "example.sh" {
			t.Errorf("expected example.sh to be filtered as a domain (accepted tradeoff), got %+v", ind)
		}
	}
}

func TestExtractIndicators_URL(t *testing.T) {
	// Asserts exactly 1 result -- the URL's own host ("Evil.Test") must NOT
	// also surface as a separate domain indicator (see ExtractIndicators' doc
	// comment on URL-vs-domain/ip suppression).
	got := ExtractIndicators("Downloaded http://Evil.Test/payload.exe#frag")
	if len(got) != 1 || got[0].Type != "url" {
		t.Fatalf("got %+v, want exactly 1 url indicator (no redundant domain hit for the URL's own host)", got)
	}
	if got[0].Value != "http://evil.test/payload.exe" {
		t.Errorf("Value = %q, want http://evil.test/payload.exe", got[0].Value)
	}
	if got[0].Confidence != 100 {
		t.Errorf("Confidence = %d, want 100", got[0].Confidence)
	}
}

func TestExtractIndicators_URL_RootPathCollapsed(t *testing.T) {
	got := ExtractIndicators("beaconing to http://Evil.Test/")
	if len(got) != 1 || got[0].Value != "http://evil.test" {
		t.Fatalf("got %+v, want http://evil.test", got)
	}
}

func TestExtractIndicators_URL_IPHostNotDoubleCounted(t *testing.T) {
	// Same suppression as the domain case, but for an IP-as-host URL.
	got := ExtractIndicators("dropped stage2 from http://45.33.32.156/s2.bin")
	if len(got) != 1 || got[0].Type != "url" {
		t.Fatalf("got %+v, want exactly 1 url indicator (no redundant ip hit for the URL's own host)", got)
	}
}

func TestExtractIndicators_HashInsideURLPath_StillExtracted(t *testing.T) {
	// Unlike domain/ip, a hash embedded in a URL's path is a distinct
	// indicator in its own right and must still be extracted alongside the url.
	got := ExtractIndicators("fetch http://cdn.example.com/0123456789abcdef0123456789abcdef")
	types := map[string]int{}
	for _, ind := range got {
		types[ind.Type]++
	}
	if types["url"] != 1 || types["hash"] != 1 {
		t.Fatalf("got %+v, want 1 url + 1 hash", got)
	}
}

func TestExtractIndicators_Hash_MD5(t *testing.T) {
	// A mechanically-constructed 32-hex-char string (not a "real" MD5 digest of
	// anything) -- the extractor only cares about hex-run length, so exact
	// length matters here more than the value being a genuine MD5 output.
	got := ExtractIndicators("MD5: 0123456789ABCDEF0123456789ABCDEF")
	if len(got) != 1 || got[0].Type != "hash" || got[0].Algorithm != "md5" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Value != "0123456789abcdef0123456789abcdef" {
		t.Errorf("Value = %q, want lowercase", got[0].Value)
	}
}

func TestExtractIndicators_Hash_SHA1(t *testing.T) {
	got := ExtractIndicators("SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
	if len(got) != 1 || got[0].Algorithm != "sha1" {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractIndicators_Hash_SHA256(t *testing.T) {
	got := ExtractIndicators("SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if len(got) != 1 || got[0].Algorithm != "sha256" {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractIndicators_CVE(t *testing.T) {
	got := ExtractIndicators("exploiting cve-2024-3094 in xz")
	if len(got) != 1 || got[0].Type != "cve" || got[0].Value != "CVE-2024-3094" || got[0].Confidence != 100 {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractIndicators_RealisticARTStdout(t *testing.T) {
	// ExtractIndicators is pure/stateless and does not dedup -- 45.33.32.156
	// legitimately appears twice here (dedup across a run is BuildRunIndicators'
	// job, tested separately in aggregate_test.go).
	text := "Scanning subnet...\n" +
		"Host up: 45.33.32.156 (198.51.100.7 filtered)\n" +
		"Retrieved banner from 45.33.32.156:445\n" +
		"Local host: 192.168.1.50 (ignored)"
	got := ExtractIndicators(text)
	uniqueIPs := map[string]bool{}
	for _, ind := range got {
		if ind.Type == "ip" {
			uniqueIPs[ind.Value] = true
		}
	}
	if len(uniqueIPs) != 2 {
		t.Fatalf("unique ips = %v, want 2 public IPs (192.168.1.50 filtered)", uniqueIPs)
	}
	if uniqueIPs["192.168.1.50"] {
		t.Error("private IP 192.168.1.50 was not filtered")
	}
}

func TestExtractIndicators_RealisticCalderaStdout(t *testing.T) {
	text := "[+] beacon established to c2.evil-domain.net\n" +
		"[+] downloading stage2 from http://c2.evil-domain.net/s2.bin\n" +
		"[+] dropped payload hash 44d88612fea8a8f36de82e1278abb02f"
	got := ExtractIndicators(text)
	types := map[string]int{}
	for _, ind := range got {
		types[ind.Type]++
	}
	if types["domain"] < 1 || types["url"] < 1 || types["hash"] != 1 {
		t.Fatalf("got %+v from %v", got, types)
	}
}

func TestExtractIndicators_NoFalsePositivesOnEmptyText(t *testing.T) {
	if got := ExtractIndicators(""); len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}
