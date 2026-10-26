"""Derive transparent console logos from the opaque brand PNGs.

The brand files (orchestrator/web/images/logo*.png) have the white background baked in, which forced
the sidebar to show the logo on a white tile. This writes, next to them:

  logo_name_ondark.png / logo_ondark.png    transparent, dark navy letters lightened  (dark, cyberpunk, slate themes)
  logo_name_onlight.png / logo_onlight.png  transparent, original colours             (light theme)

Method: "colour to alpha" against white (alpha = 1 - min(r,g,b)/255, colour recovered from the alpha),
which keeps anti-aliased edges clean. For the dark variant, recovered pixels that are dark and nearly
neutral (the navy lettering) become a light grey-blue; saturated blues and teals are left alone.

Run from the repo root:  python packaging/branding/make-console-logos.py
"""
from pathlib import Path
from PIL import Image

IMAGES = Path(__file__).resolve().parents[2] / 'orchestrator' / 'web' / 'images'
LIGHT_TEXT = (230, 237, 247)


def to_alpha(img):
    img = img.convert('RGB')
    out = Image.new('RGBA', img.size)
    src, dst = img.load(), out.load()
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = src[x, y]
            a = 1.0 - min(r, g, b) / 255.0
            if a < 0.02:
                dst[x, y] = (0, 0, 0, 0)
                continue
            rec = tuple(max(0, min(255, round((c - (1 - a) * 255) / a))) for c in (r, g, b))
            dst[x, y] = rec + (round(a * 255),)
    return out


def lighten_dark_neutrals(img):
    """Blend dark, low-saturation pixels toward LIGHT_TEXT. A smooth ramp (not a threshold) so anti-aliased
    edges move together and do not speckle."""
    out = img.copy()
    px = out.load()
    for y in range(out.height):
        for x in range(out.width):
            r, g, b, a = px[x, y]
            if a == 0:
                continue
            lum = 0.3 * r + 0.59 * g + 0.11 * b
            sat = max(r, g, b) - min(r, g, b)
            dark = max(0.0, min(1.0, (120 - lum) / 70))      # 1 when very dark, 0 from lum 120 up
            neutral = max(0.0, min(1.0, (95 - sat) / 45))    # 1 when grey/navy, 0 for saturated blues
            t = dark * neutral
            if t > 0:
                px[x, y] = tuple(round(c + (l - c) * t) for c, l in zip((r, g, b), LIGHT_TEXT)) + (a,)
    return out


for name in ('logo_name', 'logo'):
    base = to_alpha(Image.open(IMAGES / f'{name}.png'))
    base.save(IMAGES / f'{name}_onlight.png', optimize=True)
    lighten_dark_neutrals(base).save(IMAGES / f'{name}_ondark.png', optimize=True)
    print('wrote', f'{name}_onlight.png', f'{name}_ondark.png')
