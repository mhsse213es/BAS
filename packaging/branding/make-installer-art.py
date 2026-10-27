"""Generates the installer artwork from the Audspect logo (packaging/branding/clean_logo.png).

Outputs (checked in, so a build never needs Pillow):
  packaging/branding/shield.png          the shield alone, transparent background
  packaging/windows-msi/assets/WixUIDialogBmp.bmp   1480x936 welcome/finish side panel
  packaging/windows-msi/assets/WixUIBannerBmp.bmp   1480x176 header of the other pages
  orchestrator/internal/api/agentinstall/AppIcon.icns   macOS app icon (shield on a navy tile), embedded in both Mac apps

The Windows bitmaps are drawn at 4x the 370x234 / 370x44 dialog-unit size. Windows Installer stretches a bitmap to
its control, so a small bitmap is enlarged (blurry) on a scaled display while a large one is only ever reduced (sharp).

Run:  python packaging/branding/make-installer-art.py [--msi-only]   (needs Pillow; Windows fonts for the wordmark)
"""
import os
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ASSETS = os.path.join(ROOT, "packaging", "windows-msi", "assets")
os.makedirs(ASSETS, exist_ok=True)

NAVY_DEEP = (7, 20, 48)
NAVY = (11, 42, 91)
BLUE = (59, 130, 246)
CYAN = (20, 184, 230)
WHITE = (255, 255, 255)

# Output sizes: 4x of the dialog-unit-based sizes the MSI stretches them to (370x234 and 370x44 units).
DIALOG_W, DIALOG_H = 1480, 936
BANNER_W, BANNER_H = 1480, 176
SS = 2  # supersample factor for drawing, reduced with LANCZOS at the end


def font(name, size):
    for base in (r"C:\Windows\Fonts", "/usr/share/fonts/truetype/dejavu", "/System/Library/Fonts/Supplemental"):
        p = os.path.join(base, name)
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def cut_out_shield():
    """The shield from the full-size logo (it has real transparency), without the wordmark to its right."""
    im = Image.open(os.path.join(HERE, "clean_logo.png")).convert("RGBA")
    # the shield sits in the left third of the artwork; the wordmark starts further right
    left = im.crop((0, 0, 535, im.height))
    alpha = left.getchannel("A").point(lambda v: 255 if v > 60 else 0)
    return left.crop(alpha.getbbox())


def shield_fit(shield, height):
    ratio = height / shield.height
    return shield.resize((max(1, round(shield.width * ratio)), height), Image.LANCZOS)


def gradient(size, top, bottom):
    w, h = size
    g = Image.new("RGB", size)
    d = ImageDraw.Draw(g)
    for y in range(h):
        t = y / max(1, h - 1)
        d.line([(0, y), (w, y)], fill=tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3)))
    return g


def tracked(draw, xy, text, f, fill, tracking, anchor_center=True):
    """Letter-spaced text, centred on xy[0] (baseline at xy[1])."""
    widths = [draw.textlength(c, font=f) for c in text]
    total = sum(widths) + tracking * (len(text) - 1)
    x = xy[0] - total / 2 if anchor_center else xy[0]
    for c, w in zip(text, widths):
        draw.text((x, xy[1]), c, font=f, fill=fill, anchor="ls")
        x += w + tracking


def dialog_panel(shield):
    s = 4 * SS  # pixels per dialog-unit-ish (493-wide design grid scaled to 1480 = ~3 px/unit; 4*SS keeps maths simple)
    W, H = DIALOG_W * SS, DIALOG_H * SS
    panel_w = round(W * 164 / 493)
    base = Image.new("RGBA", (W, H), WHITE + (255,))
    left = gradient((panel_w, H), NAVY_DEEP, NAVY).convert("RGBA")
    d = ImageDraw.Draw(left)

    sh = shield_fit(shield, round(H * 0.34))
    left.alpha_composite(sh, ((panel_w - sh.width) // 2, round(H * 0.17)))

    f = font("segoeuib.ttf", round(H * 0.082))
    total = d.textlength("Audspect", font=f)
    x = (panel_w - total) / 2
    y = round(H * 0.665)
    d.text((x, y), "Aud", font=f, fill=WHITE, anchor="ls")
    d.text((x + d.textlength("Aud", font=f), y), "spect", font=f, fill=CYAN, anchor="ls")

    sub = font("segoeui.ttf", round(H * 0.028))
    tracked(d, (panel_w / 2, round(H * 0.725)), "CYBERSECURITY INTELLIGENCE", sub, (176, 205, 238), round(H * 0.0042))

    # thin cyan rule under the wordmark block and a solid accent along the bottom edge
    rule_w = round(panel_w * 0.30)
    d.rectangle(((panel_w - rule_w) // 2, round(H * 0.765), (panel_w + rule_w) // 2, round(H * 0.765) + SS * 3), fill=CYAN)
    d.rectangle((0, H - round(H * 0.016), panel_w, H), fill=CYAN)
    base.alpha_composite(left, (0, 0))
    ImageDraw.Draw(base).line([(panel_w, 0), (panel_w, H)], fill=(214, 222, 234), width=SS * 3)
    return base.resize((DIALOG_W, DIALOG_H), Image.LANCZOS).convert("RGB")


def banner(shield):
    W, H = BANNER_W * SS, BANNER_H * SS
    img = Image.new("RGBA", (W, H), WHITE + (255,))
    d = ImageDraw.Draw(img)
    # right-hand tag: shield and wordmark, dark text on white (the page title sits on the left)
    sh = shield_fit(shield, round(H * 0.66))
    pad = round(H * 0.24)
    img.alpha_composite(sh, (W - sh.width - pad, (H - sh.height) // 2 - round(H * 0.02)))
    f = font("segoeuib.ttf", round(H * 0.30))
    total = d.textlength("Audspect", font=f)
    x = W - sh.width - pad - round(H * 0.18) - total
    cy = H // 2 + round(H * 0.01)
    d.text((x, cy), "Aud", font=f, fill=NAVY, anchor="lm")
    d.text((x + d.textlength("Aud", font=f), cy), "spect", font=f, fill=BLUE, anchor="lm")
    # gradient rule at the bottom
    rule = round(H * 0.045)
    for i in range(W):
        t = i / (W - 1)
        c = tuple(round(NAVY[k] + (CYAN[k] - NAVY[k]) * t) for k in range(3))
        d.line([(i, H - rule), (i, H)], fill=c)
    return img.resize((BANNER_W, BANNER_H), Image.LANCZOS).convert("RGB")


def app_icon(shield):
    size = 1024
    tile = gradient((size, size), (14, 52, 110), NAVY_DEEP).convert("RGBA")
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
    if "--msi-only" not in sys.argv:
        icns = os.path.join(ROOT, "orchestrator", "internal", "api", "agentinstall", "AppIcon.icns")
        app_icon(shield).resize((512, 512), Image.LANCZOS).save(icns, sizes=[(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512)])
    print("shield", shield.size)
