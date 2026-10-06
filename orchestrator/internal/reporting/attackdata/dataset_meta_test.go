package attackdata

import "testing"

func TestDatasetMeta_EmbeddedIs161(t *testing.T) {
	m := DatasetMeta()
	if !m.Known() || m.AttackVersion != "16.1" || m.Domain != "enterprise-attack" ||
		m.SourceBundleSHA256 != "8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813" {
		t.Fatalf("embedded dataset meta = %+v", m)
	}
}

func TestParseDatasetMeta_MissingOrEmptyIsUnknown(t *testing.T) {
	for _, raw := range []string{"", "{}", `{"attack_version":null,"source_bundle_sha256":"ab"}`, `{"attack_version":""}`, "not json"} {
		if m := parseDatasetMeta([]byte(raw)); m.Known() || m.AttackVersion != "" {
			t.Fatalf("%q: want unknown, got %+v", raw, m)
		}
	}
}
