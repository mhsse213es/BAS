//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"image/png"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windigo's own HDC.AlphaBlend (used by the agent's status console) looks up
// AlphaBlend in gdi32.dll and panics -- on real Windows that function lives
// in msimg32.dll, not gdi32.dll (confirmed the hard way while building the
// agent's own logo, see agent/logo_windows.go). Same function here, called
// directly to avoid repeating that mistake.
var (
	modMsimg32     = windows.NewLazySystemDLL("msimg32.dll")
	procAlphaBlend = modMsimg32.NewProc("AlphaBlend")

	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC           = gdi32.NewProc("DeleteDC")
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [1]uint32
}

func alphaBlend(hdcDest uintptr, xDest, yDest, wDest, hDest int32, hdcSrc uintptr, xSrc, ySrc, wSrc, hSrc int32) {
	const (
		acSrcOver  = 0
		acSrcAlpha = 1
	)
	// BLENDFUNCTION is a 4-byte struct (BlendOp, BlendFlags,
	// SourceConstantAlpha, AlphaFormat); the Windows x64 ABI passes a
	// struct that size by value packed into one register.
	blendFn := uintptr(acSrcOver) | uintptr(0)<<8 | uintptr(255)<<16 | uintptr(acSrcAlpha)<<24
	procAlphaBlend.Call(
		hdcDest, uintptr(xDest), uintptr(yDest), uintptr(wDest), uintptr(hDest),
		hdcSrc, uintptr(xSrc), uintptr(ySrc), uintptr(wSrc), uintptr(hSrc),
		blendFn,
	)
}

//go:embed logo_name.png
var logoNamePNG []byte

// logoBitmap caches the decoded logo for the process lifetime -- it's drawn
// on every WM_PAINT, so decoding the embedded PNG once (not per paint)
// matters. GDI itself can't decode PNG; Go's own image/png does the
// decoding, then the pixels are copied into a GDI DIB section so the result
// is an ordinary drawable bitmap handle.
type logoBitmap struct {
	hbm  uintptr
	w, h int32
	// contentX/Y/W/H crop out the flat white margin baked into the source
	// PNG around the icon+wordmark (the asset is shared with the agent
	// status console, browser favicon, and PDF reports, so it can't be
	// re-cropped globally -- trimming happens only here, at draw time, so
	// the installer header shows less dead white space around the mark
	// without touching any other consumer of the asset).
	contentX, contentY, contentW, contentH int32
}

var cachedLogo *logoBitmap

// loadLogoBitmap decodes the embedded Audspect wordmark into a top-down
// 32bpp DIB section, ready for AlphaBlend. Returns nil on any failure
// (missing/corrupt embedded asset) -- callers must treat that as "skip
// drawing the logo" rather than a fatal error, since the installer is still
// fully usable without its logo image.
func loadLogoBitmap(hdc uintptr) *logoBitmap {
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

	var bi bitmapInfo
	bi.Header.Size = uint32(unsafe.Sizeof(bi.Header))
	bi.Header.Width = int32(w)
	bi.Header.Height = -int32(h) // negative = top-down, matches image.Image's row order
	bi.Header.Planes = 1
	bi.Header.BitCount = 32
	bi.Header.Compression = 0 // BI_RGB

	var bitsPtr uintptr
	hbm, _, _ := procCreateDIBSection.Call(hdc, uintptr(unsafe.Pointer(&bi)), 0 /*DIB_RGB_COLORS*/, uintptr(unsafe.Pointer(&bitsPtr)), 0, 0)
	if hbm == 0 || bitsPtr == 0 {
		return nil
	}

	buf := unsafe.Slice((*byte)(unsafe.Pointer(bitsPtr)), w*h*4)
	minX, minY, maxX, maxY := w, h, -1, -1
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			// color.Color.RGBA() returns alpha-premultiplied 16-bit
			// components (Go's standard image/color convention) -- GDI's
			// AlphaBlend with AC_SRC_ALPHA expects premultiplied BGRA too,
			// so no extra premultiplication math is needed here.
			rr, gg, bb, aa := img.At(bounds.Min.X+xx, bounds.Min.Y+yy).RGBA()
			i := (yy*w + xx) * 4
			buf[i+0] = byte(bb >> 8)
			buf[i+1] = byte(gg >> 8)
			buf[i+2] = byte(rr >> 8)
			buf[i+3] = byte(aa >> 8)

			// Track the bounding box of non-white, non-transparent pixels
			// so drawLogo can source-crop away the flat white margin baked
			// into this asset instead of blending the whole canvas.
			if aa>>8 > 20 && !(rr>>8 > 245 && gg>>8 > 245 && bb>>8 > 245) {
				if xx < minX {
					minX = xx
				}
				if xx > maxX {
					maxX = xx
				}
				if yy < minY {
					minY = yy
				}
				if yy > maxY {
					maxY = yy
				}
			}
		}
	}

	// A little breathing room around the tight content box -- reduces the
	// margin without butting the icon right up against the header edge.
	const pad = 5
	if maxX < 0 {
		// No non-white content found (shouldn't happen for this asset) --
		// fall back to the full canvas rather than an empty crop.
		minX, minY, maxX, maxY = 0, 0, w-1, h-1
	}
	minX = max(0, minX-pad)
	minY = max(0, minY-pad)
	maxX = min(w-1, maxX+pad)
	maxY = min(h-1, maxY+pad)

	cachedLogo = &logoBitmap{
		hbm: hbm, w: int32(w), h: int32(h),
		contentX: int32(minX), contentY: int32(minY),
		contentW: int32(maxX - minX + 1), contentH: int32(maxY - minY + 1),
	}
	return cachedLogo
}

// drawLogo alpha-blends the cached logo bitmap into destRc, preserving
// aspect ratio and centering within destRc (the logo's own aspect ratio
// rarely matches the destination rect exactly).
func drawLogo(hdc uintptr, destRc RECT) {
	logo := loadLogoBitmap(hdc)
	if logo == nil {
		return
	}
	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		return
	}
	defer procDeleteDC.Call(memDC)
	oldBmp, _, _ := procSelectObject.Call(memDC, logo.hbm)
	defer procSelectObject.Call(memDC, oldBmp)

	destW := destRc.Right - destRc.Left
	destH := destRc.Bottom - destRc.Top
	srcAspect := float64(logo.contentW) / float64(logo.contentH)
	dstAspect := float64(destW) / float64(destH)

	drawW, drawH := destW, destH
	if srcAspect > dstAspect {
		drawH = int32(float64(destW) / srcAspect)
	} else {
		drawW = int32(float64(destH) * srcAspect)
	}
	offX := destRc.Left + (destW-drawW)/2
	offY := destRc.Top + (destH-drawH)/2

	alphaBlend(hdc, offX, offY, drawW, drawH, memDC, logo.contentX, logo.contentY, logo.contentW, logo.contentH)
}
