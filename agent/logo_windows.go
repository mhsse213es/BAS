//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"image/png"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"
	"golang.org/x/sys/windows"
)

// windigo's own HDC.AlphaBlend looks up the AlphaBlend procedure in
// gdi32.dll and panics ("Failed to find AlphaBlend procedure in gdi32") --
// on real Windows that function lives in msimg32.dll, not gdi32.dll
// (confirmed via a live crash during this feature's own testing). Called
// directly via syscall instead. BLENDFUNCTION is a 4-byte struct
// (BlendOp, BlendFlags, SourceConstantAlpha, AlphaFormat); the Windows x64
// ABI passes a struct that size by value packed into one register, so it's
// built here as a single uint32 rather than passed as four separate bytes.
var (
	modMsimg32     = windows.NewLazySystemDLL("msimg32.dll")
	procAlphaBlend = modMsimg32.NewProc("AlphaBlend")
)

func alphaBlend(hdcDest win.HDC, xDest, yDest, wDest, hDest int32, hdcSrc win.HDC, xSrc, ySrc, wSrc, hSrc int32) {
	const (
		acSrcOver  = 0
		acSrcAlpha = 1
	)
	blendFn := uintptr(acSrcOver) | uintptr(0)<<8 | uintptr(255)<<16 | uintptr(acSrcAlpha)<<24
	procAlphaBlend.Call(
		uintptr(hdcDest), uintptr(xDest), uintptr(yDest), uintptr(wDest), uintptr(hDest),
		uintptr(hdcSrc), uintptr(xSrc), uintptr(ySrc), uintptr(wSrc), uintptr(hSrc),
		blendFn,
	)
}

//go:embed logo_name.png
var logoNamePNG []byte

// logoBitmap caches the decoded logo for the process lifetime -- it's
// drawn on every WM_PAINT, so decoding the embedded PNG once (not per
// paint) matters. GDI itself can't decode PNG; Go's own image/png does
// the decoding, then the pixels are copied into a GDI DIB section so the
// result is an ordinary drawable HBITMAP.
type logoBitmap struct {
	hbm  win.HBITMAP
	size win.SIZE
}

var cachedLogo *logoBitmap

// loadLogoBitmap decodes the embedded Audspect wordmark into a top-down
// 32bpp DIB section, ready for AlphaBlend. Returns nil on any failure
// (missing/corrupt embedded asset) -- callers must treat that as "skip
// drawing the logo" rather than a fatal error, since a status console is
// still fully useful without its logo image.
func loadLogoBitmap(hdc win.HDC) *logoBitmap {
	if cachedLogo != nil {
		return cachedLogo
	}
	img, err := png.Decode(bytes.NewReader(logoNamePNG))
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

	buf := unsafe.Slice(bits, w*h*4)
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			// color.Color.RGBA() returns alpha-premultiplied 16-bit
			// components (Go's standard image/color convention) -- GDI's
			// AlphaBlend with AC_SRC_ALPHA expects premultiplied BGRA
			// too, so no extra premultiplication math is needed here.
			rr, gg, bb, aa := img.At(bounds.Min.X+xx, bounds.Min.Y+yy).RGBA()
			i := (yy*w + xx) * 4
			buf[i+0] = byte(bb >> 8)
			buf[i+1] = byte(gg >> 8)
			buf[i+2] = byte(rr >> 8)
			buf[i+3] = byte(aa >> 8)
		}
	}

	cachedLogo = &logoBitmap{hbm: hbm, size: win.SIZE{Cx: int32(w), Cy: int32(h)}}
	return cachedLogo
}

// drawLogo alpha-blends the cached logo bitmap into destRc, preserving
// aspect ratio and centering within destRc (the logo's own aspect ratio
// rarely matches the destination rect exactly).
func drawLogo(hdc win.HDC, destRc win.RECT) {
	logo := loadLogoBitmap(hdc)
	if logo == nil {
		return
	}
	memDC, err := hdc.CreateCompatibleDC()
	if err != nil {
		return
	}
	defer memDC.DeleteDC()
	oldBmp, _ := memDC.SelectObjectBmp(logo.hbm)
	defer memDC.SelectObjectBmp(oldBmp)

	destW := destRc.Right - destRc.Left
	destH := destRc.Bottom - destRc.Top
	srcAspect := float64(logo.size.Cx) / float64(logo.size.Cy)
	dstAspect := float64(destW) / float64(destH)

	drawW, drawH := destW, destH
	if srcAspect > dstAspect {
		drawH = int32(float64(destW) / srcAspect)
	} else {
		drawW = int32(float64(destH) * srcAspect)
	}
	offX := destRc.Left + (destW-drawW)/2
	offY := destRc.Top + (destH-drawH)/2

	alphaBlend(hdc, offX, offY, drawW, drawH, memDC, 0, 0, logo.size.Cx, logo.size.Cy)
}
