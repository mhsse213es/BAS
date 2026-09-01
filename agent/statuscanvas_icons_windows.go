//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"image/png"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"
)

// The status console's 7 section-header icons are rasterized from the
// user-supplied SVG designs (connection/current-operation/endpoint-security-
// controls/evidence/self-protection/resources/recent-activity), rendered
// black-on-white in a browser and converted to alpha-only silhouettes
// (alpha = 255 - luminance): each embedded PNG's own RGB is discarded at
// draw time and replaced with the caller's `color` parameter, so one asset
// serves any tint the caller passes -- same reasoning as loadLogoBitmap in
// logo_windows.go, except the logo keeps its own source color and these
// icons don't.
var (
	//go:embed icon_connection.png
	iconConnectionPNG []byte
	//go:embed icon_currentoperation.png
	iconCurrentOperationPNG []byte
	//go:embed icon_endpointsecuritycontrols.png
	iconEndpointSecurityControlsPNG []byte
	//go:embed icon_evidence.png
	iconEvidencePNG []byte
	//go:embed icon_selfprotection.png
	iconSelfProtectionPNG []byte
	//go:embed icon_resources.png
	iconResourcesPNG []byte
	//go:embed icon_recentactivity.png
	iconRecentActivityPNG []byte
)

type tintedIconBitmap struct {
	hbm  win.HBITMAP
	size win.SIZE
}

// iconBitmapCache holds one tinted DIB section per (asset, color) pair for
// the process lifetime -- every real call site in this file currently
// passes colMuted, but the cache key includes color so a future caller
// passing a different color still gets correct (not stale) tinting.
var iconBitmapCache = map[string]*tintedIconBitmap{}

// loadTintedIcon decodes an embedded icon PNG, replaces every pixel's RGB
// with color (keeping the source alpha as-is, premultiplied by that alpha
// to match GDI's AC_SRC_ALPHA expectation), and caches the resulting DIB
// section. Returns nil on any failure -- callers must treat that as "skip
// drawing this icon" rather than a fatal error.
func loadTintedIcon(hdc win.HDC, key string, raw []byte, color win.COLORREF) *tintedIconBitmap {
	cacheKey := fmt.Sprintf("%s-%06x", key, uint32(color)&0xffffff)
	if b, ok := iconBitmapCache[cacheKey]; ok {
		return b
	}

	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w <= 0 || h <= 0 {
		return nil
	}

	var bi win.BITMAPINFO
	bi.BmiHeader.SetBiSize()
	bi.BmiHeader.Width = int32(w)
	bi.BmiHeader.Height = -int32(h) // negative = top-down, matches image.Image's row order
	bi.BmiHeader.Planes = 1
	bi.BmiHeader.BitCount = co.BITCOUNT_32
	bi.BmiHeader.Compression = co.BI_RGB

	hbm, bits, err := hdc.CreateDIBSection(&bi, co.DIB_COLORS_RGB, 0, 0)
	if err != nil || bits == nil {
		return nil
	}

	r, g, b := color.Red(), color.Green(), color.Blue()
	buf := unsafe.Slice(bits, w*h*4)
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			_, _, _, aa := img.At(bounds.Min.X+xx, bounds.Min.Y+yy).RGBA()
			a8 := byte(aa >> 8)
			i := (yy*w + xx) * 4
			// Premultiply the tint color by the source alpha -- GDI's
			// AlphaBlend with AC_SRC_ALPHA expects premultiplied BGRA,
			// same convention loadLogoBitmap relies on via
			// image/color.Color.RGBA() already being premultiplied.
			buf[i+0] = byte(uint16(b) * uint16(a8) / 255)
			buf[i+1] = byte(uint16(g) * uint16(a8) / 255)
			buf[i+2] = byte(uint16(r) * uint16(a8) / 255)
			buf[i+3] = a8
		}
	}

	tb := &tintedIconBitmap{hbm: hbm, size: win.SIZE{Cx: int32(w), Cy: int32(h)}}
	iconBitmapCache[cacheKey] = tb
	return tb
}

// drawTintedIcon alpha-blends a cached tinted icon bitmap into a size x
// size square at (x, y) -- the same (hdc, x, y, size, color) signature
// every drawIconX function already used, so no call site changes.
func drawTintedIcon(hdc win.HDC, key string, raw []byte, x, y, size int, color win.COLORREF) {
	icon := loadTintedIcon(hdc, key, raw, color)
	if icon == nil {
		return
	}
	memDC, err := hdc.CreateCompatibleDC()
	if err != nil {
		return
	}
	defer memDC.DeleteDC()
	oldBmp, _ := memDC.SelectObjectBmp(icon.hbm)
	defer memDC.SelectObjectBmp(oldBmp)

	alphaBlend(hdc, int32(x), int32(y), int32(size), int32(size), memDC, 0, 0, icon.size.Cx, icon.size.Cy)
}
