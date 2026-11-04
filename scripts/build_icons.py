#!/usr/bin/env python3
"""Derive every committed desktop icon artifact from one generated master PNG.

Dev-only asset builder (needs Pillow; never part of any install path):

    python3 scripts/build_icons.py <master.png>

The master is the raw 1024x1024 image-generation output: the icon tile on a
plain near-black background. This script extracts the tile, rescales it to a
full-frame 1024x1024 RGBA canvas with a squircle alpha mask, and writes into
apps/desktop/src-tauri/icons/:

  icon-1024.png  masked RGBA master (the committed source of truth)
  icon.icns      PNG-based ICNS container (ic07..ic12) for the macOS .app
  icon.png       32x32 RGBA (the Linux install copies this verbatim)
  icon.ico       16..256 RGBA (Windows bundler)

and the web dashboard brand mark:

  web/logo.png   96x96 RGBA (served at /logo.png, also the favicon)

Rerun with a new master to redesign; outputs are byte-stable for the same
input and Pillow version.
"""
from pathlib import Path
import io
import struct
import sys

from PIL import Image, ImageDraw

ICONS = Path(__file__).resolve().parents[1] / "apps/desktop/src-tauri/icons"
WEB_LOGO = Path(__file__).resolve().parents[1] / "web/logo.png"
ICNS_CHUNKS = ((32, "ic11"), (64, "ic12"), (128, "ic07"),
               (256, "ic08"), (512, "ic09"), (1024, "ic10"))
ICO_SIZES = (16, 32, 48, 64, 128, 256)
SQUIRCLE_RADIUS = 0.225  # of the side; matches the generated tile's corners


def tile_bbox(image):
    """Bounding box of the tile, assuming a near-black plain background."""
    gray = image.convert("L").point(lambda value: 255 if value > 12 else 0)
    left, top, right, bottom = gray.getbbox()
    inset = 2  # drop the tile's own half-transparent edge fringe
    return (left + inset, top + inset, right - inset, bottom - inset)


def masked_master(master):
    image = master.convert("RGB").crop(tile_bbox(master))
    image = image.resize((1024, 1024), Image.LANCZOS).convert("RGBA")
    mask = Image.new("L", (1024, 1024), 0)
    radius = round(1024 * SQUIRCLE_RADIUS)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, 1023, 1023], radius=radius, fill=255)
    image.putalpha(mask)
    return image


def png_bytes(image, size):
    buffer = io.BytesIO()
    image.resize((size, size), Image.LANCZOS).save(buffer, format="PNG")
    return buffer.getvalue()


def icns_bytes(image):
    payload = b""
    for size, kind in ICNS_CHUNKS:
        data = png_bytes(image, size)
        payload += kind.encode() + struct.pack(">I", len(data) + 8) + data
    return b"icns" + struct.pack(">I", len(payload) + 8) + payload


def main(argv):
    if len(argv) != 1:
        raise SystemExit(__doc__)
    master = Image.open(argv[0])
    if master.size != (1024, 1024):
        raise SystemExit(f"master must be 1024x1024, got {master.size}")
    image = masked_master(master)
    image.save(ICONS / "icon-1024.png")
    (ICONS / "icon.icns").write_bytes(icns_bytes(image))
    (ICONS / "icon.png").write_bytes(png_bytes(image, 32))
    image.save(ICONS / "icon.ico", format="ICO",
               sizes=[(size, size) for size in ICO_SIZES])
    WEB_LOGO.write_bytes(png_bytes(image, 96))
    print(f"wrote icon-1024.png icon.icns icon.png icon.ico into {ICONS} and {WEB_LOGO}")


if __name__ == "__main__":
    main(sys.argv[1:])
