//go:build windows

package main

import (
	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"
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
	hdc.DrawText(text, &rc, align|co.DT_SINGLELINE|co.DT_VCENTER|co.DT_END_ELLIPSIS)
}
