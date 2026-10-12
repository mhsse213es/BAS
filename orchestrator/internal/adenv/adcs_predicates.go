package adenv

import "slices"

// clientAuthEKUs are the Extended Key Usages that let a certificate be
// used for Kerberos/TLS client authentication (distinct from "Any
// Purpose", checked separately by IsESC2Vulnerable).
var clientAuthEKUs = []string{"Client Authentication", "Smart Card Logon", "PKINIT Client Authentication"}

func hasAnyEKU(ekus []string, want ...string) bool {
	for _, e := range ekus {
		if slices.Contains(want, e) {
			return true
		}
	}
	return false
}

// IsESC1Vulnerable reports whether t's configuration matches ESC1: it is
// published to a CA, lets the enrollee supply their own certificate
// subject, carries a client-authentication-capable EKU, and does not
// require manager approval. Any one of these being false means the
// configuration does not match this specific weakness.
func IsESC1Vulnerable(t CertTemplate) bool {
	return t.PublishedToCA &&
		t.EnrolleeSuppliesSubject &&
		!t.ManagerApprovalRequired &&
		hasAnyEKU(t.EKUs, clientAuthEKUs...)
}

// IsESC2Vulnerable reports whether t's configuration matches ESC2: the
// same enrollee-supplied-subject and no-approval conditions as ESC1, but
// with the "Any Purpose" EKU (or an empty EKU list, which behaves as Any
// Purpose on schema-version-1 templates) instead of a single named
// client-auth EKU.
func IsESC2Vulnerable(t CertTemplate) bool {
	return t.PublishedToCA &&
		t.EnrolleeSuppliesSubject &&
		!t.ManagerApprovalRequired &&
		(len(t.EKUs) == 0 || hasAnyEKU(t.EKUs, "Any Purpose"))
}

// IsESC3Vulnerable reports whether t's configuration matches ESC3: it is
// published to a CA and carries the Certificate Request Agent EKU, which
// lets its holder request certificates on behalf of other principals.
func IsESC3Vulnerable(t CertTemplate) bool {
	return t.PublishedToCA && hasAnyEKU(t.EKUs, "Certificate Request Agent")
}

// HasClientAuthEKU reports whether t carries a client-authentication-capable
// EKU -- the property that makes an issued certificate usable to authenticate
// as a principal. Exposed for ESC6, where enrollment plus an arbitrary SAN on
// such a template yields authentication as another principal.
func HasClientAuthEKU(t CertTemplate) bool {
	return hasAnyEKU(t.EKUs, clientAuthEKUs...)
}

// IsESC6Vulnerable reports whether ca carries the EDITF_ATTRIBUTESUBJECTALTNAME2
// policy flag, which lets any requester specify an arbitrary SAN on an issued
// certificate -- ESC6. Unlike ESC1, this does not depend on a template's
// EnrolleeSuppliesSubject: the CA applies it to every request.
func IsESC6Vulnerable(ca CertificateAuthority) bool {
	return ca.EditfAttributeSubjectAltName2
}

// IsESC8Vulnerable reports whether ca exposes an HTTP web-enrollment endpoint
// without Extended Protection for Authentication -- the ESC8 NTLM-relay target.
// A relay does not need the attacker's own enrollment rights; it coerces and
// relays another principal's authentication, so this is a CA-property check
// only.
func IsESC8Vulnerable(ca CertificateAuthority) bool {
	return ca.WebEnrollmentEnabled && !ca.RequireEPA
}

// HasTemplateWriteAccess reports whether principal holds a write-capable
// ACL right (GenericWrite/WriteOwner/WriteDacl) on t itself -- the
// ESC4-relevant configuration fact. Every template has SOME legitimate
// owner with write rights; the caller supplies the specific principal to
// check (e.g. an assessment-controlled identity), since this schema has
// no notion of which principals are "intended" owners versus not.
func HasTemplateWriteAccess(t CertTemplate, principal string) bool {
	return slices.Contains(t.WriteRights, principal)
}
