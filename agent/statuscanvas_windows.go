//go:build windows

package main

import (
	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"

	"audspect/agent/statusclient"
)

var (
	colBg       = win.RGB(0x0b, 0x14, 0x20)
	colCard     = win.RGB(0x15, 0x23, 0x38)
	colElevated = win.RGB(0x1b, 0x2a, 0x41)
	colBorder   = win.RGB(0x22, 0x32, 0x4a)
	colAccent   = win.RGB(0x2f, 0x81, 0xf7)
	colMuted    = win.RGB(0x9a, 0xa9, 0xbc)
	colSuccess  = win.RGB(0x23, 0x86, 0x36)
	colWarning  = win.RGB(0xd2, 0x99, 0x22)
	colDanger   = win.RGB(0xda, 0x36, 0x33)
	colText     = win.RGB(0xe6, 0xed, 0xf3)
)

// resources holds every GDI object the canvas needs, created once at window
// creation and released on WM_DESTROY. Recreating brushes/pens/fonts on
// every WM_PAINT would leak GDI handles (CreateFont/CreatePen/
// CreateBrushIndirect all require a matching DeleteObject).
type resources struct {
	brushBg       win.HBRUSH
	brushCard     win.HBRUSH
	brushElevated win.HBRUSH
	brushAccent   win.HBRUSH

	penBorder win.HPEN

	fontHero    win.HFONT // Segoe UI Semibold, big state word
	fontHeading win.HFONT // Segoe UI Semibold, card titles
	fontBody    win.HFONT // Segoe UI Regular, labels/values
	fontEyebrow win.HFONT // Segoe UI Semibold, small uppercase section labels
}

func solidBrush(color win.COLORREF) win.HBRUSH {
	b, _ := win.CreateBrushIndirect(&win.LOGBRUSH{Style: co.BRS_SOLID, Color: color})
	return b
}

func segoeFont(height int, weight co.FW) win.HFONT {
	_, h := dpiPos(0, height)
	f, _ := win.CreateFont(
		h, 0, 0, 0, int(weight),
		false, false, false,
		co.CHARSET_DEFAULT, co.OUT_PRECIS_DEFAULT, co.CLIP_PRECIS_DEFAULT,
		co.QUALITY_CLEARTYPE, co.PITCH_DEFAULT, co.FF_DONTCARE,
		"Segoe UI",
	)
	return f
}

func newResources() *resources {
	r := &resources{
		brushBg:       solidBrush(colBg),
		brushCard:     solidBrush(colCard),
		brushElevated: solidBrush(colElevated),
		brushAccent:   solidBrush(colAccent),
		fontHero:      segoeFont(-27, co.FW_SEMIBOLD),
		fontHeading:   segoeFont(-17, co.FW_SEMIBOLD),
		fontBody:      segoeFont(-14, co.FW_REGULAR),
		fontEyebrow:   segoeFont(-12, co.FW_SEMIBOLD),
	}
	r.penBorder, _ = win.CreatePen(co.PS_SOLID, 1, colBorder)
	return r
}

func (r *resources) release() {
	r.brushBg.DeleteObject()
	r.brushCard.DeleteObject()
	r.brushElevated.DeleteObject()
	r.brushAccent.DeleteObject()
	r.penBorder.DeleteObject()
	r.fontHero.DeleteObject()
	r.fontHeading.DeleteObject()
	r.fontBody.DeleteObject()
	r.fontEyebrow.DeleteObject()
}

func dpiRect(x, y, cx, cy int) win.RECT {
	x, y = dpiPos(x, y)
	cx, cy = dpiPos(cx, cy)
	return win.RECT{Left: int32(x), Top: int32(y), Right: int32(x + cx), Bottom: int32(y + cy)}
}

func dpiXOnly(v int) int {
	scaled, _ := dpiPos(v, 0)
	return scaled
}

// drawCard paints a rounded-rectangle card: card-colored fill, 1px border.
func (r *resources) drawCard(hdc win.HDC, rc win.RECT) {
	hdc.SelectObjectBrush(r.brushCard)
	hdc.SelectObjectPen(r.penBorder)
	cornerCx, cornerCy := dpiPos(8, 8)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cornerCx), Cy: int32(cornerCy)})
}

// drawText draws a single line of text with the given font/color, left-
// aligned (or per align) and vertically centered within rc.
func (r *resources) drawText(hdc win.HDC, text string, rc win.RECT, font win.HFONT, color win.COLORREF, align co.DT) {
	hdc.SelectObjectFont(font)
	hdc.SetTextColor(color)
	hdc.SetBkMode(co.BKMODE_TRANSPARENT)
	hdc.DrawText(text, &rc, align|co.DT_SINGLELINE|co.DT_VCENTER|co.DT_END_ELLIPSIS|co.DT_NOPREFIX)
}

func (r *resources) drawDot(hdc win.HDC, x, y, diameter int, color win.COLORREF) {
	x2, y2 := dpiPos(x, y)
	d, _ := dpiPos(diameter, 0)
	brush := solidBrush(color)
	defer brush.DeleteObject()
	hdc.SelectObjectBrush(brush)
	hdc.SelectObjectPen(r.penBorder)
	hdc.Ellipse(win.RECT{Left: int32(x2), Top: int32(y2), Right: int32(x2 + d), Bottom: int32(y2 + d)})
}

// drawIconShield draws a simple pentagon shield outline, used for the
// header badge and (reused, colored per-status) the Endpoint Security
// Controls card header.
func (r *resources) drawIconShield(hdc win.HDC, x, y, size int, color win.COLORREF) {
	pen, _ := win.CreatePen(co.PS_SOLID, 2, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	hdc.SelectObjectBrush(r.brushCard) // unfilled look: fill matches card bg
	pts := []win.POINT{
		{X: int32(x + size/2), Y: int32(y)},
		{X: int32(x + size), Y: int32(y + size/4)},
		{X: int32(x + size), Y: int32(y + size/2)},
		{X: int32(x + size/2), Y: int32(y + size)},
		{X: int32(x), Y: int32(y + size/2)},
		{X: int32(x), Y: int32(y + size/4)},
	}
	hdc.Polygon(pts)
}

// stateColor maps the same connection/lifecycle state logic used
// throughout the dashboard (ServerConnected/Paused/State) to one of the
// three semantic accent colors, so the hero card's left bar, the header
// status pill, and later cards' badges all agree on what "healthy" means.
func stateColor(s statusclient.StatusResponse) win.COLORREF {
	switch {
	case !s.ServerConnected && s.Paused:
		return colWarning
	case !s.ServerConnected:
		return colDanger
	case s.State == "quarantined" || s.State == "restricted":
		return colDanger
	default:
		return colSuccess
	}
}

func stateLabel(s statusclient.StatusResponse) string {
	switch {
	case !s.ServerConnected && s.Paused:
		return "Paused"
	case !s.ServerConnected:
		return "Disconnected"
	case s.State == "quarantined":
		return "Quarantined"
	case s.State == "restricted":
		return "Restricted"
	case s.State == "active":
		return "Active"
	default:
		return "Idle"
	}
}

func (r *resources) drawHeader(hdc win.HDC, snap StatusSnapshot) {
	badgeRc := dpiRect(24, 16, 40, 40)
	hdc.SelectObjectBrush(r.brushAccent)
	hdc.SelectObjectPen(r.penBorder)
	cx, cy := dpiPos(10, 10)
	hdc.RoundRect(badgeRc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	r.drawIconShield(hdc, int(badgeRc.Left)+dpiXOnly(10), int(badgeRc.Top)+dpiXOnly(10), dpiXOnly(20), colText)

	r.drawText(hdc, "Audspect BAS Agent", dpiRect(76, 18, 400, 22), r.fontHeading, colText, co.DT_LEFT)
	r.drawText(hdc, "Breach & Attack Simulation · Endpoint Defense Validation", dpiRect(76, 40, 500, 18), r.fontBody, colMuted, co.DT_LEFT)

	if !snap.Online {
		r.drawText(hdc, "Agent Unreachable", dpiRect(700, 26, 196, 20), r.fontBody, colDanger, co.DT_RIGHT)
		return
	}
	s := snap.Status
	r.drawDot(hdc, 700, 30, 10, stateColor(s))
	r.drawText(hdc, stateLabel(s), dpiRect(716, 26, 180, 20), r.fontBody, colText, co.DT_LEFT)
}

func (r *resources) drawHero(hdc win.HDC, snap StatusSnapshot) {
	rc := dpiRect(24, 88, 872, 100)
	r.drawCard(hdc, rc)

	if !snap.Online {
		barRc := dpiRect(24, 88, 4, 100)
		barBrush := solidBrush(colDanger)
		defer barBrush.DeleteObject()
		hdc.SelectObjectBrush(barBrush)
		hdc.Rectangle(barRc)
		r.drawText(hdc, "ENDPOINT PROTECTION STATUS", dpiRect(56, 104, 400, 16), r.fontEyebrow, colMuted, co.DT_LEFT)
		r.drawText(hdc, "Agent Unreachable", dpiRect(56, 122, 400, 36), r.fontHero, colDanger, co.DT_LEFT)
		r.drawText(hdc, "The local agent service is not responding.", dpiRect(56, 160, 500, 18), r.fontBody, colMuted, co.DT_LEFT)
		return
	}
	s := snap.Status
	accent := stateColor(s)
	barBrush := solidBrush(accent)
	defer barBrush.DeleteObject()
	hdc.SelectObjectBrush(barBrush)
	hdc.Rectangle(dpiRect(24, 88, 4, 100))

	r.drawText(hdc, "ENDPOINT PROTECTION STATUS", dpiRect(56, 104, 400, 16), r.fontEyebrow, colMuted, co.DT_LEFT)
	r.drawText(hdc, stateLabel(s), dpiRect(56, 122, 400, 36), r.fontHero, colText, co.DT_LEFT)
	desc := "Agent healthy and connected. No simulation is running."
	if s.State == "quarantined" || s.State == "restricted" {
		desc = "Agent integrity check failed — server has been notified."
	} else if s.Paused {
		desc = "Server link lost — run continues locally if one is active."
	}
	r.drawText(hdc, desc, dpiRect(56, 160, 500, 18), r.fontBody, colMuted, co.DT_LEFT)

	r.drawText(hdc, s.Hostname, dpiRect(696, 104, 176, 20), r.fontBody, colText, co.DT_RIGHT)
	r.drawText(hdc, "HOSTNAME", dpiRect(696, 124, 176, 16), r.fontEyebrow, colMuted, co.DT_RIGHT)
}
