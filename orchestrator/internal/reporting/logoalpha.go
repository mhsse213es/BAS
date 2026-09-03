package reporting

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
)

// The shipped logo PNGs are RGBA but fully opaque (alpha 255 on every pixel):
// the artwork sits on a solid white rectangle. On the light report pages that
// is invisible, but the cover is dark navy, so the mark rendered as a white
// block. The template's workaround — filter:brightness(0) invert(1) — made it
// worse rather than better: with no transparency to preserve, that filter turns
// every opaque pixel pure white, which is exactly the blank tile users saw.
//
// keyOutWhite removes the background properly, so the real artwork sits on
// whatever colour is behind it.

// whiteFloor is how light a pixel must be to count as background. Deliberately
// short of 255: the PNG is anti-aliased, so the rectangle's own pixels are not
// all exactly white.
const whiteFloor = 0xE6 // 230

// edgeFeatherFloor is how light a *retained* pixel must be before its alpha is
// softened when it borders removed background. Without this the keyed image
// keeps a hard white fringe where the artwork was anti-aliased against the
// background it no longer has.
const edgeFeatherFloor = 0xC8 // 200

// keyOutWhite makes the image's white background transparent and returns the
// re-encoded PNG. Only background CONNECTED TO THE BORDER is removed — a flood
// fill inward from the edges — so white inside the artwork (the highlights in
// the shield's aperture) is preserved. A global "remove all white" would punch
// holes through the mark itself.
//
// Returns the input unchanged if it does not decode as PNG or has no white
// border to key out, so a future logo that already has an alpha channel passes
// through untouched.
func keyOutWhite(data []byte) []byte {
	src, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return data
	}
	b := src.Bounds()
	if b.Empty() {
		return data
	}

	img := image.NewNRGBA(b)
	draw.Draw(img, b, src, b.Min, draw.Src)

	w, h := b.Dx(), b.Dy()
	idx := func(x, y int) int { return y*w + x }
	removed := make([]bool, w*h)

	isBackground := func(x, y int) bool {
		c := img.NRGBAAt(b.Min.X+x, b.Min.Y+y)
		// Fully transparent pixels are already background.
		if c.A == 0 {
			return true
		}
		return c.R >= whiteFloor && c.G >= whiteFloor && c.B >= whiteFloor
	}

	// Flood fill inward from every border pixel.
	queue := make([]int, 0, 2*(w+h))
	push := func(x, y int) {
		if x < 0 || y < 0 || x >= w || y >= h || removed[idx(x, y)] || !isBackground(x, y) {
			return
		}
		removed[idx(x, y)] = true
		queue = append(queue, idx(x, y))
	}
	for x := 0; x < w; x++ {
		push(x, 0)
		push(x, h-1)
	}
	for y := 0; y < h; y++ {
		push(0, y)
		push(w-1, y)
	}
	for len(queue) > 0 {
		p := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		x, y := p%w, p/w
		push(x-1, y)
		push(x+1, y)
		push(x, y-1)
		push(x, y+1)
	}

	anyRemoved := false
	for _, r := range removed {
		if r {
			anyRemoved = true
			break
		}
	}
	if !anyRemoved {
		return data
	}

	// Second pass: soften retained near-white pixels that touch removed
	// background, so the mark does not keep a hard white fringe. Alpha scales
	// with how far the pixel is from pure white.
	feather := make([]uint8, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if removed[idx(x, y)] {
				continue
			}
			c := img.NRGBAAt(b.Min.X+x, b.Min.Y+y)
			lightest := c.R
			if c.G > lightest {
				lightest = c.G
			}
			if c.B > lightest {
				lightest = c.B
			}
			if lightest < edgeFeatherFloor {
				continue
			}
			touching := false
			for _, d := range [4][2]int{{-1, 0}, {1, 0}, {0, -1}, {0, 1}} {
				nx, ny := x+d[0], y+d[1]
				if nx >= 0 && ny >= 0 && nx < w && ny < h && removed[idx(nx, ny)] {
					touching = true
					break
				}
			}
			if !touching {
				continue
			}
			// 255 → 0 alpha, edgeFeatherFloor → full alpha.
			span := float64(0xFF - edgeFeatherFloor)
			a := float64(0xFF-int(lightest)) / span
			feather[idx(x, y)] = uint8(a * float64(c.A))
		}
	}

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			px, py := b.Min.X+x, b.Min.Y+y
			switch {
			case removed[idx(x, y)]:
				img.SetNRGBA(px, py, color.NRGBA{})
			case feather[idx(x, y)] > 0:
				c := img.NRGBAAt(px, py)
				c.A = feather[idx(x, y)]
				img.SetNRGBA(px, py, c)
			}
		}
	}

	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return data
	}
	return out.Bytes()
}
