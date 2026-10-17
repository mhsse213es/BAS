package reporting

import (
	"html/template"
	"strings"
	"sync"
)

// Branding is the white-label configuration applied to report deliverables so an
// MSSP or partner can issue reports under their own name. It is deliberately
// small: the product/org name, an accent color, an optional logo image (as a
// data: URI so reports stay self-contained and air-gap-friendly), and a footer
// note. Empty fields fall back to the Audspect defaults.
type Branding struct {
	ProductName string `json:"productName"` // header/logo text, e.g. "Acme SecOps"
	OrgName     string `json:"orgName"`     // issuing organization, shown in footers
	AccentColor string `json:"accentColor"` // hex, e.g. "#2563eb"
	LogoDataURI string `json:"logoDataUri"` // optional base64 data: URI for a cover/header logo
	FooterNote  string `json:"footerNote"`  // optional extra footer line (e.g. "Prepared by Acme")
}

// defaultBranding is the built-in Audspect identity.
var defaultBranding = Branding{
	ProductName: "Audspect BAS",
	OrgName:     "Audspect BAS",
	AccentColor: "#2563eb",
}

var (
	_brandMu  sync.RWMutex
	_branding = defaultBranding
)

// SetBranding installs the active branding, filling any empty field from the
// Audspect default so a partial config never blanks the reports.
func SetBranding(b Branding) {
	if strings.TrimSpace(b.ProductName) == "" {
		b.ProductName = defaultBranding.ProductName
	}
	if strings.TrimSpace(b.OrgName) == "" {
		b.OrgName = defaultBranding.OrgName
	}
	if strings.TrimSpace(b.AccentColor) == "" {
		b.AccentColor = defaultBranding.AccentColor
	}
	_brandMu.Lock()
	_branding = b
	_brandMu.Unlock()
}

// GetBranding returns the active branding.
func GetBranding() Branding {
	_brandMu.RLock()
	defer _brandMu.RUnlock()
	return _branding
}

// brandView is the template-facing branding, with the logo pre-rendered as
// trusted HTML (styled text logo, or an <img> when a logo data URI is set).
type brandView struct {
	Branding
	LogoHTML  template.HTML
	AccentCSS template.CSS // validated accent color, safe to inject into a CSS context
}

// isSafeColor guards the accent color before it is injected into a CSS context:
// only #hex, rgb()/rgba(), or a bare CSS keyword are allowed, so a malicious
// stored value can't break out of the style attribute. Falls back to the
// default accent otherwise.
func isSafeColor(c string) bool {
	c = strings.TrimSpace(c)
	if c == "" || len(c) > 32 {
		return false
	}
	for _, r := range c {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '#' || r == '(' || r == ')' || r == ',' || r == '.' || r == '%' || r == ' ':
		default:
			return false
		}
	}
	return true
}

// brandingView builds the template branding view for the active branding.
func brandingView() brandView {
	b := GetBranding()
	if !isSafeColor(b.AccentColor) {
		b.AccentColor = defaultBranding.AccentColor
	}
	var logo template.HTML
	if b.LogoDataURI != "" && strings.HasPrefix(b.LogoDataURI, "data:image/") {
		logo = template.HTML(`<img src="` + template.HTMLEscapeString(b.LogoDataURI) + `" alt="logo" style="max-height:28px;vertical-align:middle">`)
	} else {
		// Styled text logo: keep the two-tone treatment for the default name,
		// otherwise render the custom name plainly (escaped).
		if b.ProductName == defaultBranding.ProductName {
			logo = template.HTML(`Aud<span>spect</span> BAS`)
		} else {
			logo = template.HTML(template.HTMLEscapeString(b.ProductName))
		}
	}
	return brandView{Branding: b, LogoHTML: logo, AccentCSS: template.CSS(b.AccentColor)}
}
