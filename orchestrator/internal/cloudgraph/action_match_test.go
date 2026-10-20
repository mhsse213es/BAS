package cloudgraph

import "testing"

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"s3:GetObject", "s3:GetObject", true},
		{"s3:GetObject", "s3:GetObjectAcl", false},
		{"s3:*", "s3:GetObject", true},
		{"s3:Get*", "s3:GetObjectAcl", true},
		{"*", "anything/at/all", true},
		{"*/read", "Microsoft.Storage/storageAccounts/read", true},
		{"*/read", "Microsoft.Storage/storageAccounts/write", false},
		{"S3:getobject", "s3:GetObject", true},
		{"", "", true},
		{"", "x", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.value); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}
