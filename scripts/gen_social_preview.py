"""Generate claude-sonar social-preview banners (1280x640) — EN + ZH."""
import math
import os
import random

from PIL import Image, ImageDraw, ImageFont, ImageFilter

W, H = 1280, 640
ROOT = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(ROOT, "..", "assets")

NAVY = (9, 13, 22)
NAVY2 = (16, 24, 39)
TEAL = (45, 212, 191)
TEAL_DIM = (45, 212, 191, 60)
BLUE = (96, 165, 250)
WHITE = (241, 245, 249)
GREY = (148, 163, 184)
DARK_PILL = (15, 23, 42, 210)
RED = (248, 113, 113)

def font(path, size, index=0):
    return ImageFont.truetype(path, size, index=index)

SEGOE_B = r"C:\Windows\Fonts\segoeuib.ttf"
SEGOE = r"C:\Windows\Fonts\segoeui.ttf"
MSYH_B = r"C:\Windows\Fonts\msyhbd.ttc"
MSYH = r"C:\Windows\Fonts\msyh.ttc"

def glow_circle(draw, cx, cy, r, color, width=2):
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=color, width=width)

def make(lang="en"):
    random.seed(42 if lang == "en" else 43)
    img = Image.new("RGB", (W, H), NAVY)
    draw = ImageDraw.Draw(img, "RGBA")

    # --- background: subtle radial glow center-right ---
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    for r in range(380, 20, -8):
        a = int(30 * (1 - r / 380))
        gd.ellipse([880 - r, 320 - r, 880 + r, 320 + r], fill=(45, 212, 191, a))
    img.paste(Image.alpha_composite(img.convert("RGBA"), glow).convert("RGB"), (0, 0))
    draw = ImageDraw.Draw(img, "RGBA")

    # --- grid dots ---
    for x in range(0, W, 40):
        for y in range(0, H, 40):
            draw.point((x, y), fill=(45, 212, 191, 16))

    # --- sonar rings (right side) ---
    cx, cy = 1000, 300
    for r in (60, 110, 160, 210):
        glow_circle(draw, cx, cy, r, TEAL_DIM, width=2)
    # sweep beam
    beam = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    bd = ImageDraw.Draw(beam)
    for ang in range(-6, 7):
        rad = math.radians(-35 + ang)
        ex = cx + 215 * math.cos(rad)
        ey = cy + 215 * math.sin(rad)
        alpha = int(120 * (1 - abs(ang) / 8))
        bd.line([cx, cy, ex, ey], fill=(45, 212, 191, alpha), width=3)
    img = Image.alpha_composite(img.convert("RGBA"), beam).convert("RGB")
    draw = ImageDraw.Draw(img, "RGBA")

    # blips on rings
    for (br, bang) in ((110, 15), (160, 200), (210, 320)):
        rad = math.radians(bang)
        bx, by = cx + br * math.cos(rad), cy + br * math.sin(rad)
        draw.ellipse([bx - 7, by - 7, bx + 7, by + 7], fill=TEAL)
        draw.ellipse([bx - 3, by - 3, bx + 3, by + 3], fill=WHITE)
    # center dot
    draw.ellipse([cx - 10, cy - 10, cx + 10, cy + 10], fill=TEAL)

    # --- left column text ---
    x0 = 90
    if lang == "en":
        f_tag = font(SEGOE_B, 22)
        f_h1 = font(SEGOE_B, 96)
        f_h2 = font(SEGOE_B, 54)
        f_body = font(SEGOE, 30)
        f_pill = font(SEGOE_B, 22)
        f_small = font(SEGOE, 21)
        tag = "READ-ONLY AUDIT · ZERO SPOOFING"
        h1 = "Claude Sonar"
        h2 = "Audit first. Fix the leak."
        body = "Local privacy & proxy-consistency audit for Claude Code and Agent Skills hosts."
        pills = ["DNS leak", "IPv6 bypass", "WebRTC exposure", "Node switching"]
        small_l = "Local evidence, not a prediction of account review"
        small_r = "No fingerprint spoofing · MIT License"
    else:
        f_tag = font(MSYH_B, 22)
        f_h1 = font(SEGOE_B, 92)
        f_h2 = font(MSYH_B, 52)
        f_body = font(MSYH, 30)
        f_pill = font(MSYH_B, 22)
        f_small = font(MSYH, 21)
        tag = "只读审计 · 零伪装"
        h1 = "Claude Sonar"
        h2 = "先体检，再堵漏。"
        body = "Claude Code 与 Agent Skills 宿主的本地隐私与代理一致性审计。"
        pills = ["域名查询泄漏", "IPv6 绕过", "WebRTC 暴露", "节点乱跳"]
        small_l = "本地证据，不代表平台审核结果"
        small_r = "不做指纹伪装 · MIT License"

    # tag pill (top-left)
    tw = draw.textlength(tag, font=f_tag)
    draw.rounded_rectangle([x0, 70, x0 + tw + 36, 118], radius=24, outline=TEAL, width=2)
    draw.text((x0 + 18, 82), tag, font=f_tag, fill=TEAL)

    # headline
    draw.text((x0, 150), h1, font=f_h1, fill=WHITE)
    # teal underline
    draw.rounded_rectangle([x0, 265, x0 + 340, 273], radius=4, fill=TEAL)

    draw.text((x0, 300), h2, font=f_h2, fill=TEAL)

    # body (wrap)
    max_w = 640
    words = body.split()
    lines, cur = [], ""
    for w_ in words:
        t = (cur + " " + w_).strip()
        if draw.textlength(t, font=f_body) > max_w:
            lines.append(cur)
            cur = w_
        else:
            cur = t
    if cur:
        lines.append(cur)
    yy = 385
    for ln in lines:
        draw.text((x0, yy), ln, font=f_body, fill=GREY)
        yy += 42

    # pills row
    px = x0
    py = yy + 28
    for p in pills:
        pw = draw.textlength(p, font=f_pill) + 34
        draw.rounded_rectangle([px, py, px + pw, py + 44], radius=22, fill=DARK_PILL, outline=(51, 65, 85), width=1)
        draw.ellipse([px + 12, py + 18, px + 20, py + 26], fill=RED)
        draw.text((px + 28, py + 8), p, font=f_pill, fill=(252, 165, 165))
        px += pw + 14

    # footer
    draw.text((x0, H - 52), small_l, font=f_small, fill=(100, 116, 139))
    rw = draw.textlength(small_r, font=f_small)
    draw.text((W - rw - 60, H - 52), small_r, font=f_small, fill=(147, 197, 253))
    # version bottom-right above footer
    f_ver = font(SEGOE_B, 26)
    draw.text((W - 150, H - 92), "v1.0.0", font=f_ver, fill=TEAL)

    out = os.path.join(ASSETS, "social-preview.jpg" if lang == "zh" else "social-preview.en.jpg")
    img.save(out, quality=92)
    print("saved", out)

if __name__ == "__main__":
    make("en")
    make("zh")
