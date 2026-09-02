//go:build windows

package main

import (
	"fmt"

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

// drawIconShieldCheck draws the ENDPOINT SECURITY CONTROLS section icon,
// rasterized from the user-supplied endpointsecuritucontrol.svg design (see
// statuscanvas_icons_windows.go).
func (r *resources) drawIconShieldCheck(hdc win.HDC, x, y, size int, color win.COLORREF) {
	drawTintedIcon(hdc, "endpointsecuritycontrols", iconEndpointSecurityControlsPNG, x, y, size, color)
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
	// Real Audspect wordmark (logo_name.png) replaces the old hand-drawn
	// badge + separately-typed "Audspect BAS Agent" title -- the logo
	// already carries the brand name, so only the descriptive subtitle
	// stays as separate text. The source PNG is a flat opaque rectangle
	// (no transparency), so a white backing chip behind it isn't strictly
	// necessary for correctness, but the rounded chip keeps it visually
	// consistent with every other rounded card on this page instead of a
	// hard-cornered rectangle sitting directly on the dark background.
	logoChipRc := dpiRect(24, 14, 148, 48)
	whiteBrush := solidBrush(win.RGB(0xff, 0xff, 0xff))
	defer whiteBrush.DeleteObject()
	hdc.SelectObjectBrush(whiteBrush)
	hdc.SelectObjectPen(r.penBorder)
	chipCx, chipCy := dpiPos(8, 8)
	hdc.RoundRect(logoChipRc, win.SIZE{Cx: int32(chipCx), Cy: int32(chipCy)})
	pad := dpiXOnly(6)
	drawLogo(hdc, win.RECT{Left: logoChipRc.Left + int32(pad), Top: logoChipRc.Top + int32(pad),
		Right: logoChipRc.Right - int32(pad), Bottom: logoChipRc.Bottom - int32(pad)})

	r.drawText(hdc, "Breach & Attack Simulation · Endpoint Defense Validation", dpiRect(184, 32, 500, 18), r.fontBody, colMuted, co.DT_LEFT)

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
	// Mirrors stateLabel's priority order exactly (paused > disconnected >
	// quarantined/restricted > default) -- this used to fall straight
	// through to the "healthy" default whenever the agent was disconnected
	// but not mid-run, showing "Disconnected" as the title next to "Agent
	// healthy and connected" as the description.
	desc := "Agent healthy and connected. No simulation is running."
	switch {
	case !s.ServerConnected && s.Paused:
		desc = "Server link lost — run continues locally if one is active."
	case !s.ServerConnected:
		desc = "Cannot reach the BAS server. The agent will keep retrying; any results are buffered locally until the link is restored."
	case s.State == "quarantined" || s.State == "restricted":
		desc = "Agent integrity check failed — server has been notified."
	}
	r.drawText(hdc, desc, dpiRect(56, 160, 500, 18), r.fontBody, colMuted, co.DT_LEFT)

	r.drawText(hdc, s.Hostname, dpiRect(696, 104, 176, 20), r.fontBody, colText, co.DT_RIGHT)
	r.drawText(hdc, "HOSTNAME", dpiRect(696, 124, 176, 16), r.fontEyebrow, colMuted, co.DT_RIGHT)
}

// drawIconNetwork draws the CONNECTION section icon, rasterized from the
// user-supplied connection.svg design (see statuscanvas_icons_windows.go).
func (r *resources) drawIconNetwork(hdc win.HDC, x, y, size int, color win.COLORREF) {
	drawTintedIcon(hdc, "connection", iconConnectionPNG, x, y, size, color)
}

// drawIconPlayCircle draws the CURRENT OPERATION section icon, rasterized
// from the user-supplied currentoperation.svg design (see
// statuscanvas_icons_windows.go).
func (r *resources) drawIconPlayCircle(hdc win.HDC, x, y, size int, color win.COLORREF) {
	drawTintedIcon(hdc, "currentoperation", iconCurrentOperationPNG, x, y, size, color)
}

func (r *resources) drawProgressBar(hdc win.HDC, rc win.RECT, pct int) {
	hdc.SelectObjectBrush(r.brushElevated)
	hdc.SelectObjectPen(r.penBorder)
	cx, cy := dpiPos(4, 4)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	if pct <= 0 {
		return
	}
	if pct > 100 {
		pct = 100
	}
	filled := rc
	filled.Right = rc.Left + (rc.Right-rc.Left)*int32(pct)/100
	fillBrush := solidBrush(colAccent)
	defer fillBrush.DeleteObject()
	hdc.SelectObjectBrush(fillBrush)
	hdc.RoundRect(filled, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
}

func (r *resources) drawConnectionCard(hdc win.HDC, snap StatusSnapshot) {
	rc := dpiRect(24, 204, 428, 190)
	r.drawCard(hdc, rc)
	r.drawIconNetwork(hdc, dpiXOnly(40), dpiXOnly(224), dpiXOnly(16), colMuted)
	r.drawText(hdc, "CONNECTION", dpiRect(60, 220, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	if !snap.Online {
		r.drawText(hdc, "Server: —", dpiRect(40, 248, 380, 18), r.fontBody, colMuted, co.DT_LEFT)
		return
	}
	s := snap.Status
	rows := []struct{ label, value string }{
		{"Server", orDash(s.ServerURL)},
		{"Link", connLinkText(s)},
		{"Lifecycle State", orDash(s.State)},
		{"Uptime", formatUptime(s.UptimeSec)},
		{"Last Heartbeat", heartbeatText(s)},
	}
	y := 248
	for _, row := range rows {
		r.drawText(hdc, row.label, dpiRect(40, y, 160, 18), r.fontBody, colMuted, co.DT_LEFT)
		r.drawText(hdc, row.value, dpiRect(200, y, 236, 18), r.fontBody, colText, co.DT_RIGHT)
		y += 26
	}
}

func connLinkText(s statusclient.StatusResponse) string {
	switch {
	case s.ServerConnected:
		return "Connected"
	case s.Paused:
		return "Paused"
	default:
		return "Disconnected"
	}
}

func heartbeatText(s statusclient.StatusResponse) string {
	if s.LastHeartbeat == nil {
		return "—"
	}
	return s.LastHeartbeat.Format("15:04:05")
}

func (r *resources) drawOperationCard(hdc win.HDC, snap StatusSnapshot) {
	a := snap.Activity
	rc := dpiRect(468, 204, 428, 190)
	r.drawCard(hdc, rc)
	r.drawIconPlayCircle(hdc, dpiXOnly(484), dpiXOnly(224), dpiXOnly(16), colMuted)
	r.drawText(hdc, "CURRENT OPERATION", dpiRect(504, 220, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	idleMeta := "Awaiting a task from the BAS console"
	if !snap.Status.ServerConnected {
		// Otherwise this reads as if a task is imminent while the agent
		// can't actually reach the server to receive one.
		idleMeta = "Disconnected — cannot receive a task until the link is restored"
	}
	title, meta, result, sweepResult, stepLine := "No active simulation", idleMeta, "", "", ""
	progress := 0
	switch {
	case a.CurrentOperation != nil && a.CurrentOperation.Running:
		op := a.CurrentOperation
		title = op.ScenarioName
		if op.TechniqueID != "" {
			title = op.TechniqueID + "  " + op.ScenarioName
		}
		if op.CurrentStep != "" {
			stepLine = "Executing: " + op.CurrentStep
		}
		meta = fmt.Sprintf("%d/%d steps · phase: %s", op.CompletedSteps, op.TotalSteps, orDash(op.Phase))
		progress = op.Progress
	case a.LastOperation != nil:
		op := a.LastOperation
		title = op.ScenarioName
		if op.TechniqueID != "" {
			title = op.TechniqueID + "  " + op.ScenarioName
		}
		meta = fmt.Sprintf("Completed · %ds", op.DurationSec)
		progress = 100
		if op.Result != "" {
			// SweepLabel disambiguates which Full Sweep layer this result
			// belongs to -- without it every layer in a 14-layer EM sweep
			// would show the same bare "Result: Evaded" with no way to
			// tell them apart.
			label := "Result"
			if op.SweepLabel != "" {
				label = "Result (" + op.SweepLabel + ")"
			}
			result = label + ": " + op.Result
		}
		// Set only on the operation that was the sweep's last layer -- one
		// rolled-up verdict across every layer this agent ran.
		if op.SweepAggregateResult != "" {
			aggLabel := op.SweepAggregateLabel
			if aggLabel == "" {
				aggLabel = "Full Sweep"
			}
			sweepResult = "Result (" + aggLabel + "): " + op.SweepAggregateResult
		}
	}
	r.drawText(hdc, title, dpiRect(484, 248, 380, 22), r.fontBody, colText, co.DT_LEFT)
	metaY, barY, resultY := 272, 300, 316
	if stepLine != "" {
		r.drawText(hdc, stepLine, dpiRect(484, metaY, 380, 18), r.fontBody, colMuted, co.DT_LEFT)
		metaY, barY, resultY = 292, 318, 334
	}
	r.drawText(hdc, meta, dpiRect(484, metaY, 380, 18), r.fontBody, colMuted, co.DT_LEFT)
	r.drawProgressBar(hdc, dpiRect(484, barY, 380, 8), progress)
	if result != "" {
		r.drawText(hdc, result, dpiRect(484, resultY, 380, 18), r.fontBody, colMuted, co.DT_LEFT)
		resultY += 18
	}
	if sweepResult != "" {
		r.drawText(hdc, sweepResult, dpiRect(484, resultY, 380, 18), r.fontBody, colMuted, co.DT_LEFT)
	}
}

// drawStatusBadge paints a small pill: elevated-colored fill, 1px border
// and centered text both in the given status color (a GDI-native
// approximation of the browser dashboard's soft-tinted badges -- true
// alpha-tinted fills would need GDI+, explicitly out of scope).
func (r *resources) drawStatusBadge(hdc win.HDC, rc win.RECT, label string, color win.COLORREF) {
	hdc.SelectObjectBrush(r.brushElevated)
	pen, _ := win.CreatePen(co.PS_SOLID, 1, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	cx, cy := dpiPos(4, 4)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	r.drawText(hdc, label, rc, r.fontEyebrow, color, co.DT_CENTER)
}

type controlRow struct {
	name, badge string
	color       win.COLORREF
}

func defenderRow(d statusclient.DefenderCtrl) controlRow {
	switch {
	case d.Present && d.RTPEnabled:
		return controlRow{"Defender RTP", "ACTIVE", colSuccess}
	case d.Present:
		return controlRow{"Defender RTP", "DEGRADED", colWarning}
	default:
		return controlRow{"Defender RTP", "ABSENT", colDanger}
	}
}

func boolRow(name string, on bool) controlRow {
	if on {
		return controlRow{name, "ACTIVE", colSuccess}
	}
	return controlRow{name, "ABSENT", colDanger}
}

func (r *resources) drawControlsCard(hdc win.HDC, c statusclient.ControlsResponse) {
	rc := dpiRect(24, 410, 872, 190)
	r.drawCard(hdc, rc)
	r.drawIconShieldCheck(hdc, dpiXOnly(40), dpiXOnly(430), dpiXOnly(16), colMuted)
	r.drawText(hdc, "ENDPOINT SECURITY CONTROLS", dpiRect(60, 426, 400, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	rows := []controlRow{
		defenderRow(c.Defender),
		boolRow("Sysmon", c.Sysmon.Present),
		boolRow("Firewall", c.Firewall.Enabled),
		boolRow("AppLocker", c.AppLocker.Enabled),
		boolRow("WDAC", c.WDAC.Enabled),
		boolRow("AMSI", c.AMSI.Enabled),
	}
	colX := []int{40, 468}
	for i, row := range rows {
		col := colX[i%2]
		y := 454 + (i/2)*44
		r.drawDot(hdc, col, y+6, 8, row.color)
		r.drawText(hdc, row.name, dpiRect(col+16, y, 200, 20), r.fontBody, colText, co.DT_LEFT)
		r.drawStatusBadge(hdc, dpiRect(col+240, y, 100, 24), row.badge, row.color)
	}
}

// drawIconClipboardCheck draws the EVIDENCE section icon, rasterized from
// the user-supplied evidence.svg design (see statuscanvas_icons_windows.go).
func (r *resources) drawIconClipboardCheck(hdc win.HDC, x, y, size int, color win.COLORREF) {
	drawTintedIcon(hdc, "evidence", iconEvidencePNG, x, y, size, color)
}

// drawIconShieldLock draws the SELF-PROTECTION section icon, rasterized
// from the user-supplied selfprotection.svg design (see
// statuscanvas_icons_windows.go).
func (r *resources) drawIconShieldLock(hdc win.HDC, x, y, size int, color win.COLORREF) {
	drawTintedIcon(hdc, "selfprotection", iconSelfProtectionPNG, x, y, size, color)
}

// drawStatTile paints an elevated-surface tile with a large value and a
// small muted caption below it -- used by Evidence, Resources, and any
// future numeric-summary card.
func (r *resources) drawStatTile(hdc win.HDC, rc win.RECT, value, label string) {
	hdc.SelectObjectBrush(r.brushElevated)
	hdc.SelectObjectPen(r.penBorder)
	cx, cy := dpiPos(6, 6)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	valueRc := rc
	valueRc.Bottom -= (rc.Bottom - rc.Top) / 3
	r.drawText(hdc, value, valueRc, r.fontHeading, colText, co.DT_LEFT)
	labelRc := rc
	labelRc.Top = valueRc.Bottom
	r.drawText(hdc, label, labelRc, r.fontEyebrow, colMuted, co.DT_LEFT)
}

func (r *resources) drawEvidenceCard(hdc win.HDC, ev statusclient.EvidenceResponse) {
	rc := dpiRect(24, 616, 428, 210)
	r.drawCard(hdc, rc)
	r.drawIconClipboardCheck(hdc, dpiXOnly(40), dpiXOnly(636), dpiXOnly(16), colMuted)
	r.drawText(hdc, "EVIDENCE · LAST RUN", dpiRect(60, 632, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	tiles := []struct{ value, label string }{
		{fmt.Sprintf("%d", ev.EventsCollected), "EVENTS COLLECTED"},
		{fmt.Sprintf("%d", ev.DefenderAlerts), "DEFENDER ALERTS"},
		{fmt.Sprintf("%d", ev.SysmonDetections), "SYSMON DETECTIONS"},
		{fmt.Sprintf("%d", ev.QueueSize), "UPLOAD QUEUE"},
	}
	tileW, tileH, gap := 186, 64, 12
	for i, t := range tiles {
		col, row := i%2, i/2
		x := 40 + col*(tileW+gap)
		y := 660 + row*(tileH+gap)
		r.drawStatTile(hdc, dpiRect(x, y, tileW, tileH), t.value, t.label)
	}
}

func (r *resources) drawSelfProtectionCard(hdc win.HDC, s statusclient.StatusResponse, ev statusclient.EvidenceResponse) {
	rc := dpiRect(468, 616, 428, 210)
	r.drawCard(hdc, rc)
	r.drawIconShieldLock(hdc, dpiXOnly(484), dpiXOnly(636), dpiXOnly(16), colMuted)
	r.drawText(hdc, "SELF-PROTECTION", dpiRect(504, 632, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	rows := []controlRow{
		healthRow("Service Running", s.ServiceRunning),
		healthRow("Policy Sync", s.State == "active" || s.State == "restricted"),
		healthRow("Evidence Queue", ev.QueueSize < 100),
		healthRow("Last Upload OK", s.LastUploadOk),
		healthRow("Server Contact", s.ServerConnected),
	}
	y := 660
	for _, row := range rows {
		r.drawDot(hdc, 484, y+6, 8, row.color)
		r.drawText(hdc, row.name, dpiRect(500, y, 220, 20), r.fontBody, colText, co.DT_LEFT)
		r.drawStatusBadge(hdc, dpiRect(756, y, 100, 24), row.badge, row.color)
		y += 28
	}
}

func healthRow(name string, healthy bool) controlRow {
	if healthy {
		return controlRow{name, "HEALTHY", colSuccess}
	}
	return controlRow{name, "CHECK", colWarning}
}

// drawIconMonitor draws the RESOURCES section icon, rasterized from the
// user-supplied resources.svg design (see statuscanvas_icons_windows.go).
func (r *resources) drawIconMonitor(hdc win.HDC, x, y, size int, color win.COLORREF) {
	drawTintedIcon(hdc, "resources", iconResourcesPNG, x, y, size, color)
}

func (r *resources) drawResourcesCard(hdc win.HDC, s statusclient.StatusResponse) {
	rc := dpiRect(24, 842, 872, 130)
	r.drawCard(hdc, rc)
	r.drawIconMonitor(hdc, dpiXOnly(40), dpiXOnly(862), dpiXOnly(16), colMuted)
	r.drawText(hdc, "RESOURCES", dpiRect(60, 858, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	tiles := []struct{ value, label string }{
		{fmt.Sprintf("%d MB", s.RamMB), "MEMORY (WORKING SET)"},
		{"v" + s.AgentVersion, "AGENT VERSION"},
		{orDash(s.AgentID), "AGENT ID"},
	}
	tileW, tileH, gap := 272, 64, 16
	for i, t := range tiles {
		x := 40 + i*(tileW+gap)
		r.drawStatTile(hdc, dpiRect(x, 886, tileW, tileH), t.value, t.label)
	}
}

// drawIconPulse draws the RECENT ACTIVITY section icon, rasterized from
// the user-supplied recentactivity.svg design (see
// statuscanvas_icons_windows.go).
func (r *resources) drawIconPulse(hdc win.HDC, x, y, size int, color win.COLORREF) {
	drawTintedIcon(hdc, "recentactivity", iconRecentActivityPNG, x, y, size, color)
}

// drawActivityCard shows the most recent 8 entries, newest first (no
// scrolling, per design) -- same data source and ordering as before.
func (r *resources) drawActivityCard(hdc win.HDC, items []statusclient.Activity) {
	rc := dpiRect(24, 988, 872, 240)
	r.drawCard(hdc, rc)
	r.drawIconPulse(hdc, dpiXOnly(40), dpiXOnly(1008), dpiXOnly(16), colMuted)
	r.drawText(hdc, "RECENT ACTIVITY", dpiRect(60, 1004, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	if len(items) == 0 {
		r.drawText(hdc, "No recent activity recorded.", dpiRect(40, 1032, 800, 18), r.fontBody, colMuted, co.DT_LEFT)
		return
	}
	max := len(items)
	if max > 8 {
		max = 8
	}
	y := 1032
	for _, item := range items[:max] {
		r.drawDot(hdc, 40, y+5, 6, colAccent)
		r.drawText(hdc, item.Time.Format("15:04:05"), dpiRect(56, y, 80, 18), r.fontBody, colMuted, co.DT_LEFT)
		r.drawText(hdc, item.Event, dpiRect(148, y, 720, 18), r.fontBody, colText, co.DT_LEFT)
		y += 22
	}
}

// drawButton paints a rounded rect button: accent-filled for primary,
// elevated-filled with a border for secondary. Returns rc unchanged so
// callers can pass it straight into a buttonHitRect.
func (r *resources) drawButton(hdc win.HDC, rc win.RECT, label string, primary bool) win.RECT {
	if primary {
		hdc.SelectObjectBrush(r.brushAccent)
	} else {
		hdc.SelectObjectBrush(r.brushElevated)
	}
	hdc.SelectObjectPen(r.penBorder)
	cx, cy := dpiPos(6, 6)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	r.drawText(hdc, label, rc, r.fontBody, colText, co.DT_CENTER)
	return rc
}
