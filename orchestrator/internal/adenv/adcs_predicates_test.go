package adenv

import "testing"

func TestIsESC1Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		tmpl CertTemplate
		want bool
	}{
		{
			name: "vulnerable: published, enrollee SAN, client auth EKU, no approval",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: false},
			want: true,
		},
		{
			name: "mitigated by manager approval",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: true},
			want: false,
		},
		{
			name: "not vulnerable: enrollee cannot supply subject",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: false, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: false},
			want: false,
		},
		{
			name: "empty EKU list is ESC2's shape, not ESC1's",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: nil, ManagerApprovalRequired: false},
			want: false,
		},
		{
			name: "not published to any CA -- cannot be requested at all",
			tmpl: CertTemplate{PublishedToCA: false, EnrolleeSuppliesSubject: true, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: false},
			want: false,
		},
	}
	for _, c := range cases {
		if got := IsESC1Vulnerable(c.tmpl); got != c.want {
			t.Errorf("%s: IsESC1Vulnerable() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsESC2Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		tmpl CertTemplate
		want bool
	}{
		{
			name: "vulnerable: any-purpose EKU",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: []string{"Any Purpose"}, ManagerApprovalRequired: false},
			want: true,
		},
		{
			name: "vulnerable: empty EKU list behaves as any-purpose",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: nil, ManagerApprovalRequired: false},
			want: true,
		},
		{
			name: "mitigated by manager approval",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: nil, ManagerApprovalRequired: true},
			want: false,
		},
		{
			name: "a specific client-auth EKU alone is ESC1's shape, not ESC2's",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: false},
			want: false,
		},
	}
	for _, c := range cases {
		if got := IsESC2Vulnerable(c.tmpl); got != c.want {
			t.Errorf("%s: IsESC2Vulnerable() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsESC3Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		tmpl CertTemplate
		want bool
	}{
		{
			name: "vulnerable: published, Certificate Request Agent EKU",
			tmpl: CertTemplate{PublishedToCA: true, EKUs: []string{"Certificate Request Agent"}},
			want: true,
		},
		{
			name: "not published to any CA",
			tmpl: CertTemplate{PublishedToCA: false, EKUs: []string{"Certificate Request Agent"}},
			want: false,
		},
		{
			name: "no agent EKU",
			tmpl: CertTemplate{PublishedToCA: true, EKUs: []string{"Client Authentication"}},
			want: false,
		},
	}
	for _, c := range cases {
		if got := IsESC3Vulnerable(c.tmpl); got != c.want {
			t.Errorf("%s: IsESC3Vulnerable() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHasTemplateWriteAccess(t *testing.T) {
	tmpl := CertTemplate{WriteRights: []string{"Domain Admins", "PKI Admins"}}
	if !HasTemplateWriteAccess(tmpl, "PKI Admins") {
		t.Error("expected HasTemplateWriteAccess to return true for a listed principal")
	}
	if HasTemplateWriteAccess(tmpl, "Domain Users") {
		t.Error("expected HasTemplateWriteAccess to return false for a principal NOT in WriteRights")
	}
	if HasTemplateWriteAccess(CertTemplate{}, "Domain Admins") {
		t.Error("expected HasTemplateWriteAccess to return false when WriteRights is empty")
	}
}
