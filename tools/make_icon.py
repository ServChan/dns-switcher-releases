"""Рисует значок программы: синий скруглённый квадрат с белым глобусом.

Запуск: python tools/make_icon.py  (нужен Pillow). Создаёт assets/icon.ico
для exe и assets/icon-64.rgba для окна.
"""
from pathlib import Path
from PIL import Image, ImageDraw

S = 1024  # рисуем крупно и уменьшаем, чтобы края были гладкими
ACCENT = (0, 95, 184, 255)
WHITE = (255, 255, 255, 255)

img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle([40, 40, S - 40, S - 40], radius=220, fill=ACCENT)

c, r, w = S // 2, 290, 46
d.ellipse([c - r, c - r, c + r, c + r], outline=WHITE, width=w)            # контур
d.ellipse([c - r * 0.45, c - r, c + r * 0.45, c + r], outline=WHITE, width=w)  # меридиан
d.line([c - r, c, c + r, c], fill=WHITE, width=w)                           # экватор
for dy in (-r * 0.52, r * 0.52):                                            # параллели
    half = (r * r - dy * dy) ** 0.5 - w * 0.3
    d.line([c - half, c + dy, c + half, c + dy], fill=WHITE, width=int(w * 0.8))

out = Path(__file__).resolve().parent.parent / "assets"
out.mkdir(exist_ok=True)
img.resize((256, 256), Image.LANCZOS).save(
    out / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
)
(out / "icon-64.rgba").write_bytes(img.resize((64, 64), Image.LANCZOS).tobytes())
img.resize((256, 256), Image.LANCZOS).save(out / "icon.png")
print("ok", out)
