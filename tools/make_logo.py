"""Generate the CanaryGuard logo, app icon and favicon.

Pure Pillow, no external assets. Run from the repo root:

    python tools/make_logo.py

Outputs:
    assets/logo.svg      vector mark (README, docs)
    assets/logo.png      512x512 transparent mark
    assets/icon.svg      vector app icon
    assets/icon.png      256x256 rounded app icon
    assets/icon.ico      multi-size Windows icon
    static/favicon.png   64x64 dashboard favicon
    static/logo.png      128x128 transparent mark (dashboard header)

The PNG and SVG versions share the same 1024x1024 coordinate space so they
stay visually identical.
"""

import math
import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NAVY = (11, 18, 32, 255)
TEAL_TOP = (20, 184, 166, 255)
TEAL_BOTTOM = (13, 90, 84, 255)
BORDER = (94, 234, 212, 255)
GOLD = (251, 191, 36, 255)
GOLD_DARK = (217, 119, 6, 255)
BEAK = (249, 115, 22, 255)
EYE = (11, 18, 32, 255)

# ---------------------------------------------------------------- geometry --

SHIELD_PATH = (
    "M 248 208 L 776 208 Q 816 208 816 248 L 816 470 "
    "C 816 690 700 806 512 904 C 324 806 208 690 208 470 "
    "L 208 248 Q 208 208 248 208 Z"
)

TAIL = [
    [(430, 606), (330, 700), (348, 742), (452, 660)],
    [(434, 664), (344, 744), (362, 782), (462, 714)],
]

LEGS = [
    [(486, 706), (472, 790)],
    [(548, 706), (562, 790)],
]
TOES = [
    [(472, 790), (450, 804)],
    [(472, 790), (494, 804)],
    [(562, 790), (540, 804)],
    [(562, 790), (584, 804)],
]

BODY = (398, 452, 630, 724)
NECK = (516, 402, 640, 508)
HEAD = (500, 330, 650, 480)
BEAK_PTS = [(636, 384), (760, 418), (636, 452)]
WING = (444, 536, 574, 690)
EYE_BOX = (596, 382, 624, 410)
EYE_HL = (601, 386, 611, 396)


def _bezier(p0, p1, p2, p3, steps=48):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        x = (u ** 3) * p0[0] + 3 * (u ** 2) * t * p1[0] + 3 * u * (t ** 2) * p2[0] + (t ** 3) * p3[0]
        y = (u ** 3) * p0[1] + 3 * (u ** 2) * t * p1[1] + 3 * u * (t ** 2) * p2[1] + (t ** 3) * p3[1]
        pts.append((x, y))
    return pts


def crest_points(size):
    """Shield outline in a 1024x1024 space, sampled for Pillow."""
    pts = [(248, 208), (776, 208)]
    for deg in range(-90, 1, 4):
        a = math.radians(deg)
        pts.append((776 + 40 * math.cos(a), 248 + 40 * math.sin(a)))
    pts.append((816, 470))
    pts += _bezier((816, 470), (816, 690), (700, 806), (512, 904))
    pts += _bezier((512, 904), (324, 806), (208, 690), (208, 470))[1:]
    pts.append((208, 248))
    for deg in range(180, 271, 4):
        a = math.radians(deg)
        pts.append((248 + 40 * math.cos(a), 248 + 40 * math.sin(a)))

    k = size / 1024.0
    return [(x * k, y * k) for x, y in pts]


def _gradient(size, top, bottom, y0, y1):
    img = Image.new("RGBA", (size, size))
    d = ImageDraw.Draw(img)
    span = max(1, y1 - y0)
    for y in range(y0, y1 + 1):
        t = (y - y0) / span
        c = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(4))
        d.line([(0, y), (size, y)], fill=c)
    return img


def draw_mark(size=1024, ss=3):
    """Transparent shield + canary bird."""
    s = size * ss
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    pts = crest_points(s)

    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).polygon(pts, fill=255)

    grad = _gradient(s, TEAL_TOP, TEAL_BOTTOM, int(0.20 * s), int(0.89 * s))
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)

    def P(x, y):
        return (x / 1024.0 * s, y / 1024.0 * s)

    def box(b):
        return [P(b[0], b[1]), P(b[2], b[3])]

    def shifted(b, dx, dy):
        return [P(b[0] + dx, b[1] + dy), P(b[2] + dx, b[3] + dy)]

    def overlay(fn):
        """Draw translucent shapes on a layer, then blend them properly."""
        layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        fn(ImageDraw.Draw(layer))
        return Image.alpha_composite(img, layer)

    # shield rim
    d.line(pts + [pts[0]], fill=BORDER, width=max(2, int(0.018 * s)), joint="curve")

    # soft drop shadow under the bird
    shadow = (4, 30, 28, 80)

    def draw_shadow(sd):
        for poly in TAIL:
            sd.polygon([P(x + 6, y + 18) for x, y in poly], fill=shadow)
        for b in (BODY, NECK, HEAD, WING):
            sd.ellipse(shifted(b, 6, 18), fill=shadow)

    img = overlay(draw_shadow)
    d = ImageDraw.Draw(img)

    # tail feathers (behind the body)
    for poly in TAIL:
        d.polygon([P(x, y) for x, y in poly], fill=GOLD)

    # legs
    lw = max(2, int(0.013 * s))
    for a, b in LEGS + TOES:
        d.line([P(*a), P(*b)], fill=GOLD_DARK, width=lw)

    # body + neck + head
    d.ellipse(box(BODY), fill=GOLD)
    d.ellipse(box(NECK), fill=GOLD)
    d.ellipse(box(HEAD), fill=GOLD)

    # wing
    d.ellipse(box(WING), fill=GOLD_DARK)
    d.arc(box((456, 560, 566, 678)), 200, 340, fill=GOLD, width=max(2, int(0.008 * s)))
    d.arc(box((460, 588, 558, 682)), 205, 335, fill=GOLD, width=max(2, int(0.008 * s)))

    # head highlight
    img = overlay(lambda hd: hd.ellipse(box((522, 352, 570, 400)),
                                        fill=(253, 230, 138, 70)))
    d = ImageDraw.Draw(img)

    # beak
    d.polygon([P(x, y) for x, y in BEAK_PTS], fill=BEAK)

    # eye
    d.ellipse(box(EYE_BOX), fill=EYE)
    d.ellipse(box(EYE_HL), fill=(255, 255, 255, 255))

    return img.resize((size, size), Image.LANCZOS)


def rounded_icon(size=1024, ss=2):
    """Navy rounded square with the mark."""
    s = size * ss
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=int(0.22 * s), fill=NAVY)

    mark = draw_mark(size=s, ss=1)
    inner = int(s * 0.82)
    mark = mark.resize((inner, inner), Image.LANCZOS)
    off = (s - inner) // 2
    img.paste(mark, (off, off), mark)
    return img.resize((size, size), Image.LANCZOS)


# --------------------------------------------------------------------- svg --

def _hex(color):
    return "#%02x%02x%02x" % color[:3]


def _svg_poly(points):
    return " ".join(f"{x},{y}" for x, y in points)


def _ellipse_svg(box, fill):
    cx = (box[0] + box[2]) / 2.0
    cy = (box[1] + box[3]) / 2.0
    rx = (box[2] - box[0]) / 2.0
    ry = (box[3] - box[1]) / 2.0
    return f'  <ellipse cx="{cx:g}" cy="{cy:g}" rx="{rx:g}" ry="{ry:g}" fill="{fill}"/>'


def _svg_defs():
    return f'''  <defs>
    <linearGradient id="shield" gradientUnits="userSpaceOnUse" x1="512" y1="205" x2="512" y2="911">
      <stop offset="0" stop-color="{_hex(TEAL_TOP)}"/>
      <stop offset="1" stop-color="{_hex(TEAL_BOTTOM)}"/>
    </linearGradient>
  </defs>'''


def mark_body():
    """Shapes only, in the shared 1024x1024 coordinate space."""
    tail = "\n".join(
        f'  <polygon points="{_svg_poly(poly)}" fill="{_hex(GOLD)}"/>' for poly in TAIL)
    legs = "\n".join(
        f'  <line x1="{a[0]}" y1="{a[1]}" x2="{b[0]}" y2="{b[1]}" '
        f'stroke="{_hex(GOLD_DARK)}" stroke-width="13" stroke-linecap="round"/>'
        for a, b in LEGS + TOES)
    eye_cx = (EYE_BOX[0] + EYE_BOX[2]) / 2.0
    eye_cy = (EYE_BOX[1] + EYE_BOX[3]) / 2.0
    hl_cx = (EYE_HL[0] + EYE_HL[2]) / 2.0
    hl_cy = (EYE_HL[1] + EYE_HL[3]) / 2.0
    return f'''  <path d="{SHIELD_PATH}" fill="url(#shield)" stroke="{_hex(BORDER)}" stroke-width="18" stroke-linejoin="round"/>
{tail}
{legs}
{_ellipse_svg(BODY, _hex(GOLD))}
{_ellipse_svg(NECK, _hex(GOLD))}
{_ellipse_svg(HEAD, _hex(GOLD))}
  <ellipse cx="546" cy="376" rx="24" ry="24" fill="#fde68a" fill-opacity="0.27"/>
{_ellipse_svg(WING, _hex(GOLD_DARK))}
  <path d="M 470 566 Q 508 646 556 670" fill="none" stroke="{_hex(GOLD)}" stroke-width="8" stroke-linecap="round"/>
  <path d="M 466 602 Q 506 674 552 694" fill="none" stroke="{_hex(GOLD)}" stroke-width="8" stroke-linecap="round"/>
  <polygon points="{_svg_poly(BEAK_PTS)}" fill="{_hex(BEAK)}"/>
  <circle cx="{eye_cx:g}" cy="{eye_cy:g}" r="{(EYE_BOX[2] - EYE_BOX[0]) / 2.0:g}" fill="{_hex(EYE)}"/>
  <circle cx="{hl_cx:g}" cy="{hl_cy:g}" r="{(EYE_HL[2] - EYE_HL[0]) / 2.0:g}" fill="#ffffff" fill-opacity="0.92"/>'''


def mark_svg():
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="512" height="512" role="img" aria-label="CanaryGuard">
{_svg_defs()}
{mark_body()}
</svg>
'''


def icon_svg():
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="256" height="256" role="img" aria-label="CanaryGuard icon">
{_svg_defs()}
  <rect x="0" y="0" width="1024" height="1024" rx="225" fill="{_hex(NAVY)}"/>
  <g transform="translate(92 92) scale(0.82)">
{mark_body()}
  </g>
</svg>
'''


def main():
    assets = os.path.join(ROOT, "assets")
    static = os.path.join(ROOT, "static")
    os.makedirs(assets, exist_ok=True)
    os.makedirs(static, exist_ok=True)

    logo = draw_mark(1024)
    logo.resize((512, 512), Image.LANCZOS).save(os.path.join(assets, "logo.png"))
    logo.resize((128, 128), Image.LANCZOS).save(os.path.join(static, "logo.png"))

    icon = rounded_icon(1024)
    icon.resize((256, 256), Image.LANCZOS).save(os.path.join(assets, "icon.png"))
    icon.resize((64, 64), Image.LANCZOS).save(os.path.join(static, "favicon.png"))

    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    icon.resize((256, 256), Image.LANCZOS).save(
        os.path.join(assets, "icon.ico"), sizes=ico_sizes)

    with open(os.path.join(assets, "logo.svg"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(mark_svg())
    with open(os.path.join(assets, "icon.svg"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(icon_svg())

    print("wrote:")
    for path in ("assets/logo.png", "assets/logo.svg", "assets/icon.png",
                 "assets/icon.svg", "assets/icon.ico", "static/favicon.png",
                 "static/logo.png"):
        full = os.path.join(ROOT, path.replace("/", os.sep))
        print(f"  {path}  ({os.path.getsize(full)} bytes)")


if __name__ == "__main__":
    main()
