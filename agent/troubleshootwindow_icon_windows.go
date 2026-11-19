//go:build windows

package main

import (
	_ "embed"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"
)

// troubleshootShieldPNG is the dotted-shield logo, shown as this window's title-bar icon.
//
//go:embed troubleshoot_shield.png
var troubleshootShieldPNG []byte

// loadTroubleshootIcon builds the shield as an icon from the embedded PNG. Windows Vista and later
// accept PNG data in CreateIconFromResourceEx. It returns 0 on failure, and the window then keeps
// its default icon.
func loadTroubleshootIcon() win.HICON {
	icon, err := win.CreateIconFromResourceEx(troubleshootShieldPNG, 0x00030000,
		win.SIZE{Cx: 64, Cy: 64}, co.LR_DEFAULTCOLOR)
	if err != nil {
		return 0
	}
	return icon
}

// setTroubleshootIcon puts the icon on the window's title bar (small) and in the task switcher (big).
func setTroubleshootIcon(hWnd win.HWND, icon win.HICON) {
	if icon == 0 {
		return
	}
	_, _ = hWnd.SendMessage(co.WM_SETICON, win.WPARAM(0), win.LPARAM(icon)) // ICON_SMALL
	_, _ = hWnd.SendMessage(co.WM_SETICON, win.WPARAM(1), win.LPARAM(icon)) // ICON_BIG
}
