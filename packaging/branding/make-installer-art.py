"""Generates the installer artwork from the Audspect shield (installer/logo.ico).

Outputs (checked in, so a build never needs Pillow):
  packaging/branding/shield.png          the dotted shield alone, transparent background
  packaging/windows-msi/assets/WixUIDialogBmp.bmp   493x312 welcome/finish side panel
  packaging/windows-msi/assets/WixUIBannerBmp.bmp   493x58 header of the other pages
  orchestrator/internal/api/agentinstall/AppIcon.icns   macOS app icon (shield on a navy tile), embedded in both Mac apps

Run:  python packaging/branding/make-installer-art.py      (needs Pillow; Windows fonts for the wordmark)
"""
import os
from collections import deque

from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ASSETS = os.path.join(ROOT, "packaging", "windows-msi", "assets")
os.makedirs(ASSETS, exist_ok=True)

NAVY_DEEP = (7, 20, 48)
NAVY = (11, 42, 91)
BLUE = (59, 130, 246)
CYAN = (20, 184, 230)
WHITE = (255, 255, 255)


def font(name, size):
    for base in (r"C:\Windows\Fonts", "/usr/share/fonts/truetype/dejavu", "/System/Library/Fonts/Supplemental"):
        p = os.path.join(base, name)
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def cut_out_shield():
    """The shield from the icon, with the white tile around it removed (flood fill from the outside, so the
    light parts inside the shield are kept) and its soft edge turned into real transparency."""
    im = Image.open(os.path.join(ROOT, "installer", "logo.ico"))
    im.size = (256, 256)
    im = im.convert("RGBA")
    w, h = im.size
    px = im.load()

    def background(p):
        r, g, b, a = p
        return a < 20 or (r > 238 and g > 238 and b > 238)

    seen = [[False] * w for _ in range(h)]
    q = deque()
    for x in range(w):
        for y in (0, h - 1):
            q.append((x, y))
    for y in range(h):
        for x in (0, w - 1):
            q.append((x, y))
    while q:
        x, y = q.popleft()
        if x < 0 or y < 0 or x >= w or y >= h or seen[y][x] or not background(px[x, y]):
            continue
        seen[y][x] = True
        q.extend(((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)))

    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    po = out.load()
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if seen[y][x]:
                continue
            near_bg = any(
                0 <= x + dx < w and 0 <= y + dy < h and seen[y + dy][x + dx]
                for dx in (-1, 0, 1) for dy in (-1, 0, 1)
            )
            if near_bg:
                # colour-to-alpha against white on the edge ring only: removes the white halo
                m = min(r, g, b)
                alpha = max(0, min(255, int((255 - m) * 255 / max(1, 255 - 40))))
                if alpha == 0:
                    continue
                k = alpha / 255.0
                r = int(max(0, min(255, (r - 255 * (1 - k)) / k)))
                g = int(max(0, min(255, (g - 255 * (1 - k)) / k)))
                b = int(max(0, min(255, (b - 255 * (1 - k)) / k)))
                po[x, y] = (r, g, b, alpha)
            else:
                po[x, y] = (r, g, b, 255)
    out = out.crop(out.getbbox())
    return out


def shield_fit(shield, height):
    ratio = height / shield.height
    return shield.resize((max(1, int(shield.width * ratio)), height), Image.LANCZOS)


def gradient(size, top, bottom):
    w, h = size
    g = Image.new("RGB", size)
    d = ImageDraw.Draw(g)
    for y in range(h):
        t = y / max(1, h - 1)
        d.line([(0, y), (w, y)], fill=tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)))
    return g


def dotted_field(size, color, step=9, radius=1):
    """Subtle dot grid, echoing the dotted shield."""
    layer = Image.new("RGBA", size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for y in range(step // 2, size[1], step):
        for x in range(step // 2, size[0], step):
            d.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color)
    return layer


def glow(canvas, center, radius, color, strength):
    layer = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    d.ellipse((center[0] - radius, center[1] - radius, center[0] + radius, center[1] + radius), fill=color + (strength,))
    layer = layer.filter(ImageFilter.GaussianBlur(radius * 0.55))
    canvas.alpha_composite(layer)


def wordmark(draw, xy, size, anchor="ls"):
    f = font("segoeuib.ttf", size)
    x, y = xy
    draw.text((x, y), "Aud", font=f, fill=WHITE, anchor=anchor)
    off = draw.textlength("Aud", font=f)
    draw.text((x + off, y), "spect", font=f, fill=CYAN, anchor=anchor)


def dialog_panel(shield):
    S = 4  # supersample
    W, H = 493 * S, 312 * S
    panel_w = 164 * S
    base = Image.new("RGBA", (W, H), WHITE + (255,))
    left = gradient((panel_w, H), NAVY_DEEP, NAVY).convert("RGBA")
    left.alpha_composite(dotted_field((panel_w, H), BLUE + (38,), step=9 * S, radius=S))
    glow(left, (panel_w // 2, 108 * S), 70 * S, CYAN, 70)
    sh = shield_fit(shield, 104 * S)
    left.alpha_composite(sh, ((panel_w - sh.width) // 2, 60 * S))
    d = ImageDraw.Draw(left)
    f = font("segoeuib.ttf", 25 * S)
    total = d.textlength("Audspect", font=f)
    wordmark(d, ((panel_w - total) / 2, 198 * S), 25 * S)
    sub = font("segoeui.ttf", 9 * S)
    tag = "CYBERSECURITY INTELLIGENCE"
    d.text((panel_w // 2, 214 * S), tag, font=sub, fill=(170, 200, 235), anchor="ms")
    # cyan accent rule along the bottom of the panel
    d.rectangle((0, H - 5 * S, panel_w, H), fill=CYAN)
    base.alpha_composite(left, (0, 0))
    # hairline between panel and page
    ImageDraw.Draw(base).line([(panel_w, 0), (panel_w, H)], fill=(205, 215, 230), width=S)
    return base.resize((493, 312), Image.LANCZOS).convert("RGB")


def banner(shield):
    S = 4
    W, H = 493 * S, 58 * S
    img = Image.new("RGBA", (W, H), WHITE + (255,))
    d = ImageDraw.Draw(img)
    # right-hand tag: shield and wordmark, dark text on white (the page title sits on the left)
    sh = shield_fit(shield, 40 * S)
    img.alpha_composite(sh, (W - sh.width - 14 * S, (H - sh.height) // 2 - 1 * S))
    f = font("segoeuib.ttf", 13 * S)
    total = d.textlength("Audspect", font=f)
    x = W - sh.width - 14 * S - 10 * S - total
    d.text((x, H // 2 + 1 * S), "Aud", font=f, fill=NAVY, anchor="lm")
    d.text((x + d.textlength("Aud", font=f), H // 2 + 1 * S), "spect", font=f, fill=BLUE, anchor="lm")
    # gradient rule at the bottom
    for i in range(W):
        t = i / (W - 1)
        c = tuple(int(NAVY[k] + (CYAN[k] - NAVY[k]) * t) for k in range(3))
        d.line([(i, H - 3 * S), (i, H)], fill=c)
    return img.resize((493, 58), Image.LANCZOS).convert("RGB")


def app_icon(shield):
    S = 4
    size = 1024
    tile = gradient((size, size), (14, 52, 110), NAVY_DEEP).convert("RGBA")
    tile.alpha_composite(dotted_field((size, size), BLUE + (46,), step=36, radius=3))
    glow(tile, (size // 2, size // 2), 330, CYAN, 80)
    sh = shield_fit(shield, int(size * 0.62))
    tile.alpha_composite(sh, ((size - sh.width) // 2, (size - sh.height) // 2))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=int(size * 0.2237), fill=255)
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(tile, (0, 0), mask)
    return out


if __name__ == "__main__":
    shield = cut_out_shield()
    shield.save(os.path.join(HERE, "shield.png"))
    dialog_panel(shield).save(os.path.join(ASSETS, "WixUIDialogBmp.bmp"))
    banner(shield).save(os.path.join(ASSETS, "WixUIBannerBmp.bmp"))
    icns = os.path.join(ROOT, "orchestrator", "internal", "api", "agentinstall", "AppIcon.icns")
    app_icon(shield).resize((512, 512), Image.LANCZOS).save(icns, sizes=[(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512)])
    print("shield", shield.size)
