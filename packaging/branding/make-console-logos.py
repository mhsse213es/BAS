"""Build the console logos from the clean, transparent brand artwork (packaging/branding/clean_logo.png).

Writes into orchestrator/web/images/:

  logo_name_ondark.png / logo_ondark.png    wordmark+shield / shield only, for dark backgrounds
                                            (the dark-blue "Aud" lettering is lightened so it stays readable)
  logo_name_onlight.png / logo_onlight.png  same crops with the original colours, for the Light theme

The source canvas is mostly empty padding, so each output is cropped to its artwork and scaled to
HEIGHT px (about 3x the size it is shown at, for sharp rendering on high-density screens).

Run from the repo root:  python packaging/branding/make-console-logos.py
"""
from pathlib import Path
from PIL import Image

HERE = Path(__file__).resolve().parent
IMAGES = HERE.parents[1] / 'orchestrator' / 'web' / 'images'
HEIGHT = 132
LIGHT_TEXT = (226, 238, 255)


def alpha_bbox(img, threshold=12):
    return img.getchannel('A').point(lambda a: 255 if a > threshold else 0).getbbox()


def split_column(img, bbox):
    """x of the widest empty vertical gap between the shield and the lettering."""
    a = img.getchannel('A').load()
    x0, y0, x1, y1 = bbox
    best, run_start, best_start = 0, None, None
    for x in range(x0, x1):
        empty = all(a[x, y] < 12 for y in range(y0, y1))
        if empty and run_start is None:
            run_start = x
        if (not empty or x == x1 - 1) and run_start is not None:
            if x - run_start > best:
                best, best_start = x - run_start, run_start
            run_start = None
    return best_start + best // 2


def lighten_dark(img, x_from):
    """Blend dark pixels right of x_from (the lettering) toward LIGHT_TEXT with a smooth ramp."""
    out = img.copy()
    px = out.load()
    for y in range(out.height):
        for x in range(x_from, out.width):
            r, g, b, a = px[x, y]
            if a == 0:
                continue
            lum = 0.3 * r + 0.59 * g + 0.11 * b
            t = max(0.0, min(1.0, (135 - lum) / 70))
            if t:
                px[x, y] = tuple(round(c + (l - c) * t) for c, l in zip((r, g, b), LIGHT_TEXT)) + (a,)
    return out


def scaled(img):
    return img.resize((round(img.width * HEIGHT / img.height), HEIGHT), Image.LANCZOS)


src = Image.open(HERE / 'clean_logo.png').convert('RGBA')
bbox = alpha_bbox(src)
cut = split_column(src, bbox)
word = src.crop(bbox)
mark = src.crop((bbox[0], bbox[1], cut, bbox[3]))
mark = mark.crop(alpha_bbox(mark))

for name, art, lettering_from in (('logo_name', word, cut - bbox[0]), ('logo', mark, None)):
    scaled(art).save(IMAGES / f'{name}_onlight.png', optimize=True)
    dark = lighten_dark(art, lettering_from) if lettering_from else art
    scaled(dark).save(IMAGES / f'{name}_ondark.png', optimize=True)
    print('wrote', f'{name}_onlight.png', f'{name}_ondark.png')
