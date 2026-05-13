---
title: mscp.admin_utils.banner_generator
description: "Banner image generator for the macOS Security Compliance Project (mSCP)."
sidebar:
  order: 1
---

> Source: [`src/mscp/admin_utils/banner_generator.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/admin_utils/banner_generator.py)

Banner image generator for the macOS Security Compliance Project (mSCP).

Produces per-platform banner images (macOS, iOS, visionOS) in light, dark,
and high-contrast (8 px stroke) modes by compositing the mSCP logo with
platform-specific text and a rounded colored divider.

Background removal uses a BFS flood-fill from image edges (``isolate_logo``).
Logo pixels are recolored per platform via ``change_color``.

Public entry point: ``generate_mscp_banners()``

Configuration keys consumed from ``config``:
    images_dir  — directory containing ``mscp_logo.png``; output is written here.

Output filename pattern:
    mscp_banner_<platform>_<mode>.png
    where platform ∈ {macos, ios, visionos} and mode ∈ {light, dark, both_8px}.


## Functions

### color_dist

```python
color_dist(a: tuple, b: tuple) -> int
```


### isolate_logo

```python
isolate_logo(logo_path: str, threshold: int=40) -> Image.Image
```

Remove the background of a logo image using a flood-fill from the edges.

Assumes the top-left pixel is representative of the background color.
Edge-reachable pixels within *threshold* color distance (sum of absolute
RGB channel differences) of that background are made fully transparent.
The result is cropped to the tightest bounding box of remaining opaque content.

**Args**

- **`logo_path`** — Path to the source image (any PIL-supported format).
- **`threshold`** — Maximum RGB channel distance to treat a pixel as background.

**Returns**

- RGBA Image with background removed and cropped to content bounds.


### font

```python
font(font_path: str, size: int, bold: bool=False, italic: bool=False) -> ImageFont.FreeTypeFont
```


### draw_text

```python
draw_text(draw: ImageDraw.ImageDraw, xy: tuple, text: str, fnt: ImageFont.FreeTypeFont, style: dict) -> None
```


### change_color

```python
change_color(image: Image.Image, old_color: tuple, new_color: tuple, tolerance: int=0) -> Image.Image
```


### generate_mscp_banners

```python
generate_mscp_banners(sp: Yaspin, args: argparse.Namespace) -> None
```

*Decorators:* `@conditional_inject_spinner()`

Generate MSCP banner images for all supported platforms and display modes.

Reads ``mscp_logo.png`` from ``config["images_dir"]``, removes its background,
recolors it per platform, and composites it with title text onto a transparent
RGBA canvas.  Nine files are written in total (3 platforms × 3 modes).

**Args**

- **`sp`** — Yaspin spinner instance injected by ``@conditional_inject_spinner``.
- **`args`** — Parsed CLI arguments from argparse.
