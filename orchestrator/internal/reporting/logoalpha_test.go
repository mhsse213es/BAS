package reporting

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"
)

func decodePNG(t *testing.T, data []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return img
}

// The shipped logo is opaque on every pixel, which is exactly why the cover
// rendered a blank tile. After keying, its corners must be transparent.
func TestKeyOutWhite_ShippedLogoBecomesTransparent(t *testing.T) {
	raw, err := os.ReadFile("../../wwwroot/images/logo.png")
	if err != nil {
		t.Skipf("logo not present in this checkout: %v", err)
	}

	before := decodePNG(t, raw)
	if _, _, _, a := before.At(0, 0).RGBA(); a == 0 {
		t.Skip("logo already has a transparent background; keying is a no-op")
	}

	img := decodePNG(t, keyOutWhite(raw))
	b := img.Bounds()
	corners := [][2]int{
		{b.Min.X, b.Min.Y}, {b.Max.X - 1, b.Min.Y},
		{b.Min.X, b.Max.Y - 1}, {b.Max.X - 1, b.Max.Y - 1},
	}
	for _, c := range corners {
		if _, _, _, a := img.At(c[0], c[1]).RGBA(); a != 0 {
			t.Errorf("corner (%d,%d) still opaque (alpha %d) — the white background survived", c[0], c[1], a>>8)
		}
	}

	// The artwork itself must survive: some pixel must still be fully opaque.
	opaque := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a>>8 == 0xFF {
				opaque++
			}
		}
	}
	if opaque == 0 {
		t.Fatal("keying erased the whole image — nothing opaque left")
	}
	t.Logf("%d opaque pixels retained of %d", opaque, b.Dx()*b.Dy())
}

// White INSIDE the artwork must survive. A global "remove every white pixel"
// would punch holes through the mark; only background reachable from the border
// is removed.
func TestKeyOutWhite_KeepsEnclosedWhite(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 9, 9))
	for y := 0; y < 9; y++ {
		for x := 0; x < 9; x++ {
			img.SetNRGBA(x, y, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}) // white everywhere
		}
	}
	// A closed dark ring at radius 3, leaving white outside AND enclosed white inside.
	for y := 2; y <= 6; y++ {
		for x := 2; x <= 6; x++ {
			if x == 2 || x == 6 || y == 2 || y == 6 {
				img.SetNRGBA(x, y, color.NRGBA{0x10, 0x20, 0x30, 0xFF})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode: %v", err)
	}

	got := decodePNG(t, keyOutWhite(buf.Bytes()))
	if _, _, _, a := got.At(0, 0).RGBA(); a != 0 {
		t.Error("outer white was not removed")
	}
	if _, _, _, a := got.At(4, 4).RGBA(); a>>8 != 0xFF {
		t.Errorf("enclosed white at (4,4) has alpha %d, want 255 — the fill leaked through the ring", a>>8)
	}
	if _, _, _, a := got.At(2, 4).RGBA(); a>>8 != 0xFF {
		t.Errorf("ring pixel at (2,4) has alpha %d, want 255 — the artwork was eaten", a>>8)
	}
}

// An image that is already transparent, or has no white border at all, must
// come back byte-identical rather than be re-encoded.
func TestKeyOutWhite_PassesThroughWhenNothingToKey(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			img.SetNRGBA(x, y, color.NRGBA{0x20, 0x40, 0x60, 0xFF})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode: %v", err)
	}
	in := buf.Bytes()
	if got := keyOutWhite(in); !bytes.Equal(got, in) {
		t.Error("an image with no white border was re-encoded; want the input returned unchanged")
	}
}

// Non-PNG input must not panic or corrupt — the loader hands us whatever is on
// disk.
func TestKeyOutWhite_NonPNGReturnedUnchanged(t *testing.T) {
	in := []byte("not a png at all")
	if got := keyOutWhite(in); !bytes.Equal(got, in) {
		t.Error("non-PNG input was modified")
	}
}
