//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"image"
	"image/color"
	"image/png"
	"math"
	"unsafe"
)

// logo.png is a square (48x48) frame extracted from agent/logo.ico -- the
// same rounded-corner Audspect wordmark badge already used for the
// installer window and both status consoles this session. Embedding a
// plain PNG (decodable via Go's stdlib) rather than the .ico itself avoids
// needing an ICO-directory parser just to get pixels to composite onto.
//
//go:embed logo.png
var logoPNGBytes []byte

var (
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procCreateBitmap       = gdi32.NewProc("CreateBitmap")
	procCreateIconIndirect = user32.NewProc("CreateIconIndirect")
)

// bitmapInfoHeader mirrors Win32's BITMAPINFOHEADER. CreateDIBSection wants
// a BITMAPINFO*, but BITMAPINFO's trailing bmiColors[1] array is unused for
// 32bpp BI_RGB (no palette), so a bare BITMAPINFOHEADER pointer works --
// same technique agent/logo_windows.go already relies on via windigo's
// wrapper type.
type bitmapInfoHeader struct {
	Size          uint32
	Width, Height int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// iconInfo mirrors Win32's ICONINFO. Go's automatic struct alignment pads
// HbmMask to an 8-byte boundary after the three 4-byte fields, matching
// the real C layout -- no manual padding field needed here (unlike
// notifyIconData in main.go, which interleaves fields in a way that does
// need it).
type iconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

// rgb is a plain (non-premultiplied, non-COLORREF) color for the status
// dot composited onto the tray icon.
type rgb struct{ r, g, b byte }

// Matches clrGreen/clrAmber/clrRed in window.go exactly (#238636 / #d29922
// / #da3633) -- the same healthy/warning/unhealthy palette used everywhere
// else in this app, so the tray icon's dot reads as the same signal as the
// status window's own indicators.
var (
	badgeGreen = rgb{0x23, 0x86, 0x36}
	badgeAmber = rgb{0xd2, 0x99, 0x22}
	badgeRed   = rgb{0xda, 0x36, 0x33}
)

var (
	brandedLogoImg   image.Image
	brandedIconCache = map[rgb]uintptr{}
)

func loadBrandedLogo() image.Image {
	if brandedLogoImg != nil {
		return brandedLogoImg
	}
	img, err := png.Decode(bytes.NewReader(logoPNGBytes))
	if err != nil {
		return nil
	}
	brandedLogoImg = img
	return img
}

// buildStatusIcon composites a colored status dot (bottom-right, with a
// white ring for contrast against the notification area's own background,
// which varies by Windows theme) onto the branded Audspect logo and
// returns a real Win32 HICON. Called once per color at startup and cached
// for the process lifetime -- replaces the old trayIconGreen/Amber/Red
// pattern that previously just loaded a generic Windows stock icon
// (shield/asterisk/hand) per color. Returns 0 on any failure; callers must
// fall back to a stock icon rather than treat this as fatal -- a tray icon
// beats no tray icon.
func buildStatusIcon(c rgb) uintptr {
	if h, ok := brandedIconCache[c]; ok {
		return h
	}
	base := loadBrandedLogo()
	if base == nil {
		return 0
	}
	b := base.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return 0
	}

	// Badge geometry: bottom-right corner, ~19% of the icon's width as the
	// dot's radius, with a white ring (~22% of the radius) for contrast.
	radius := float64(w) * 0.19
	ringW := radius * 0.22
	cx := float64(w) - radius - 1
	cy := float64(h) - radius - 1

	composited := image.NewRGBA(b)
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			dx, dy := float64(xx)-cx, float64(yy)-cy
			dist := math.Sqrt(dx*dx + dy*dy)
			switch {
			case dist <= radius-ringW:
				composited.Set(xx, yy, color.RGBA{R: c.r, G: c.g, B: c.b, A: 255})
			case dist <= radius:
				composited.Set(xx, yy, color.RGBA{R: 255, G: 255, B: 255, A: 255})
			default:
				composited.Set(xx, yy, base.At(b.Min.X+xx, b.Min.Y+yy))
			}
		}
	}

	icon := imageToHIcon(composited)
	if icon != 0 {
		brandedIconCache[c] = icon
	}
	return icon
}

// imageToHIcon converts a decoded RGBA image into a real Win32 HICON: a
// 32bpp top-down BGRA color bitmap carrying real per-pixel alpha (the
// "ARGB icon" trick supported since XP) plus a fully-opaque 1bpp AND mask
// CreateIconIndirect still requires but which Windows ignores once the
// color bitmap's own alpha channel is present.
func imageToHIcon(img *image.RGBA) uintptr {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	var bi bitmapInfoHeader
	bi.Size = uint32(unsafe.Sizeof(bi))
	bi.Width = int32(w)
	bi.Height = -int32(h) // negative = top-down, matches image.Image's row order
	bi.Planes = 1
	bi.BitCount = 32
	bi.Compression = 0 // BI_RGB

	var bits unsafe.Pointer
	hbmColor, _, _ := procCreateDIBSection.Call(
		0, uintptr(unsafe.Pointer(&bi)), 0 /* DIB_RGB_COLORS */, uintptr(unsafe.Pointer(&bits)), 0, 0,
	)
	if hbmColor == 0 || bits == nil {
		return 0
	}
	buf := unsafe.Slice((*byte)(bits), w*h*4)
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			// color.Color.RGBA() returns alpha-premultiplied 16-bit
			// components (Go's standard image/color convention) -- exactly
			// what a 32bpp ARGB icon's color bitmap expects, no extra
			// premultiplication math needed. Mirrors
			// agent/logo_windows.go's identical DIB fill loop.
			rr, gg, bb, aa := img.At(b.Min.X+xx, b.Min.Y+yy).RGBA()
			i := (yy*w + xx) * 4
			buf[i+0] = byte(bb >> 8)
			buf[i+1] = byte(gg >> 8)
			buf[i+2] = byte(rr >> 8)
			buf[i+3] = byte(aa >> 8)
		}
	}

	// CreateBitmap's docs call lpvBits==NULL content "undefined" -- pass an
	// explicit zeroed buffer instead so every mask bit reliably means
	// "opaque, use the color bitmap's own alpha" rather than relying on
	// undocumented behavior. 1bpp DDB rows are WORD-aligned.
	maskStride := ((w + 15) / 16) * 2
	maskBits := make([]byte, maskStride*h)
	hbmMask, _, _ := procCreateBitmap.Call(uintptr(w), uintptr(h), 1, 1, uintptr(unsafe.Pointer(&maskBits[0])))
	if hbmMask == 0 {
		procDeleteObject.Call(hbmColor)
		return 0
	}

	ii := iconInfo{FIcon: 1, HbmMask: hbmMask, HbmColor: hbmColor}
	hIcon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	// CreateIconIndirect copies both bitmaps into the icon it creates --
	// the originals must be freed here or they leak for the process
	// lifetime (small in practice, since this only runs 3 times, at
	// startup, but real).
	procDeleteObject.Call(hbmColor)
	procDeleteObject.Call(hbmMask)
	return hIcon
}
