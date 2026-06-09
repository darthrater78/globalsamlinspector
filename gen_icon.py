"""Generate saml.ico — dark shield with teal lock."""
from PIL import Image, ImageDraw
import math

def draw_icon(size: int) -> Image.Image:
    # RGB with solid background — transparent ICOs render badly in Windows shell / PyInstaller
    img = Image.new('RGB', (size, size), (24, 26, 36))
    d = ImageDraw.Draw(img)

    s = size
    BG      = (24, 26, 36)      # dark navy
    SHIELD  = (37, 40, 55)      # slightly lighter panel
    TEAL    = (78, 201, 176)    # #4ec9b0
    TEAL_D  = (52, 148, 128)    # darker teal for depth

    # ── Background: solid fill (no transparency — needed for correct ICO rendering)
    d.rectangle([0, 0, s, s], fill=BG)

    # ── Shield shape ─────────────────────────────────────────────────────────
    # A shield: flat top-left/top-right corners, rounded bottom that ends in a point.
    # We'll build it as a polygon approximation.
    mx = s * 0.13   # horizontal margin
    ty = s * 0.10   # top y
    by = s * 0.92   # bottom tip y
    # Top edge x coords
    xl = mx
    xr = s - mx
    # "shoulder" height where sides start curving inward
    sh = s * 0.62

    # Build the shield polygon (clockwise from top-left)
    pts = []
    # Top-left corner arc
    corner_r = int(s * 0.07)
    for a in range(180, 271, 5):
        pts.append((xl + corner_r + corner_r * math.cos(math.radians(a)),
                    ty + corner_r + corner_r * math.sin(math.radians(a))))
    # Top-right corner arc
    for a in range(270, 361, 5):
        pts.append((xr - corner_r + corner_r * math.cos(math.radians(a)),
                    ty + corner_r + corner_r * math.sin(math.radians(a))))
    # Right side down to shoulder
    pts.append((xr, sh))
    # Right curve inward to tip
    ctrl_steps = 30
    for i in range(ctrl_steps + 1):
        t = i / ctrl_steps
        # Quadratic bezier: P0=(xr, sh), P1=(xr, by*0.82), P2=(s/2, by)
        p0x, p0y = xr, sh
        p1x, p1y = xr, by * 0.82
        p2x, p2y = s / 2, by
        bx = (1-t)**2 * p0x + 2*(1-t)*t * p1x + t**2 * p2x
        by2 = (1-t)**2 * p0y + 2*(1-t)*t * p1y + t**2 * p2y
        pts.append((bx, by2))
    # Left curve from tip to shoulder (mirror)
    for i in range(ctrl_steps, -1, -1):
        t = i / ctrl_steps
        p0x, p0y = xl, sh
        p1x, p1y = xl, by * 0.82
        p2x, p2y = s / 2, by
        bx = (1-t)**2 * p0x + 2*(1-t)*t * p1x + t**2 * p2x
        by2 = (1-t)**2 * p0y + 2*(1-t)*t * p1y + t**2 * p2y
        pts.append((bx, by2))

    d.polygon(pts, fill=SHIELD)

    # Thin teal border on shield
    d.line(pts + [pts[0]], fill=TEAL, width=max(1, int(s * 0.022)))

    # ── Lock shackle (arc) ────────────────────────────────────────────────────
    lck_cx = s / 2
    lck_cy = s * 0.47
    shackle_r  = s * 0.155
    shackle_w  = max(2, int(s * 0.065))
    shackle_top = lck_cy - shackle_r * 1.1

    bbox = [
        lck_cx - shackle_r, shackle_top,
        lck_cx + shackle_r, shackle_top + shackle_r * 2,
    ]
    d.arc(bbox, start=200, end=340, fill=TEAL, width=shackle_w)

    # ── Lock body ─────────────────────────────────────────────────────────────
    bw = s * 0.38
    bh = s * 0.28
    bx0 = lck_cx - bw / 2
    by0 = lck_cy - bh * 0.1
    bx1 = lck_cx + bw / 2
    by1 = by0 + bh
    body_r = int(s * 0.045)
    d.rounded_rectangle([bx0, by0, bx1, by1], radius=body_r, fill=TEAL)

    # Lock body highlight strip (top edge)
    d.rounded_rectangle([bx0, by0, bx1, by0 + bh * 0.18], radius=body_r, fill=TEAL_D)

    # ── Keyhole ───────────────────────────────────────────────────────────────
    kh_cx = lck_cx
    kh_cy = by0 + bh * 0.38
    kh_r  = s * 0.052
    # Circle
    d.ellipse([kh_cx - kh_r, kh_cy - kh_r, kh_cx + kh_r, kh_cy + kh_r], fill=BG)
    # Stem
    stem_w = kh_r * 0.9
    stem_h = bh * 0.32
    d.rectangle([kh_cx - stem_w, kh_cy + kh_r * 0.5,
                 kh_cx + stem_w, kh_cy + kh_r * 0.5 + stem_h], fill=BG)

    return img


# Generate all required sizes for a quality .ico
SIZES = [256, 128, 64, 48, 32, 16]
frames = [draw_icon(sz) for sz in SIZES]

# Save as RGB ICO — solid background ensures correct rendering in Windows shell and PyInstaller
frames[0].save(
    'saml.ico',
    format='ICO',
    sizes=[(sz, sz) for sz in SIZES],
    append_images=frames[1:],
)
print(f"saml.ico written ({len(SIZES)} sizes: {SIZES})")

# Also save a PNG preview
frames[0].save('icon_preview.png')
print("icon_preview.png written")
