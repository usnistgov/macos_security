#!/usr/bin/env python3
"""Generate a gettext POT file for YAML-driven content (baselines/profiles/rules).

Why this exists
--------------
Your templates call `t(profile.description_key, profile.description)` and similar, where
the translation *keys* are computed at runtime from YAML-derived models.

Static extractors (e.g., `pybabel extract`) cannot discover those keys, so we generate
`messages.pot` from the loaded Baseline/Rule models instead.

What it extracts
----------------
- Baseline: title/description (optional; included when present)
- Profile: section/description
- Rule: title/discussion

Key format (stable)
-------------------
- baseline.<baseline_name>.title
- baseline.<baseline_name>.description
- profile.<slug(section)>.section
- profile.<slug(section)>.description
- rule.<rule_id>.title
- rule.<rule_id>.discussion

Each msgid is the *key*. The English fallback text is emitted as an auto-comment
to provide translators context.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from babel.messages.catalog import Catalog
from babel.messages.pofile import write_po

from ..classes import Baseline


def slugify(value: str, *, default: str = "item") -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = value.strip("_")
    return value or default


def _nonempty(s: Any) -> bool:
    return isinstance(s, str) and s.strip() != ""


def _iter_baseline_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return

    # directory: common baseline filename patterns
    for patt in ("*.yml", "*.yaml"):
        yield from sorted(path.rglob(patt))


def _safe_get(obj: Any, name: str, default: Any = None) -> Any:
    # works for dicts and pydantic models
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def add_message(
    catalog: Catalog,
    key: str,
    english: str,
    *,
    location: tuple[str, int] | None = None,
    comment_prefix: str | None = None,
) -> None:
    """Add a message with auto-comments containing the English fallback."""
    if not key:
        return

    comments: list[str] = []
    if comment_prefix:
        comments.append(comment_prefix)
    if _nonempty(english):
        # Keep comments readable; gettext tools handle long comments fine.
        comments.append(f"English: {english.strip()}")

    catalog.add(
        id=key,
        string=None,
        auto_comments=comments or None,
        locations=[location] if location else None,
    )


def generate_language(args: argparse.Namespace) -> None:
    catalog = Catalog(
        domain=args.domain,
        project="macOS Security Compliance Project",
        charset="utf-8",
    )

    baseline_path: Path = Path(args.baseline)

    if baseline_path.is_dir():
        baseline_files = sorted(baseline_path.glob("*.y*ml"))
    elif baseline_path.is_file():
        baseline_files = [baseline_path]
    else:
        raise FileNotFoundError(f"Baseline path not found: {baseline_path}")

    if not baseline_files:
        print("No baseline YAML files found.")

    for bf in baseline_files:
        try:
            baseline = Baseline.from_file(
                file_path=bf,
                os_name=args.os_name,
                os_version=args.os_version,
                custom=args.custom,
            )
        except Exception as e:
            print(f"WARN: Failed to load baseline {bf}: {e}")
            continue

        bname = _safe_get(baseline, "name", bf.stem)

        # Baseline title/description (only if present)
        btitle = _safe_get(baseline, "title", "")
        bdesc = _safe_get(baseline, "description", "")
        if _nonempty(btitle):
            add_message(
                catalog,
                f"baseline.{bname}.title",
                btitle,
                location=(str(bf), 1),
                comment_prefix=f"Baseline title ({bname})",
            )
        if _nonempty(bdesc):
            add_message(
                catalog,
                f"baseline.{bname}.description",
                bdesc,
                location=(str(bf), 1),
                comment_prefix=f"Baseline description ({bname})",
            )

        profiles = _safe_get(baseline, "profile", []) or []
        for prof in profiles:
            section = _safe_get(prof, "section", "")
            desc = _safe_get(prof, "description", "")
            pslug = slugify(section, default="profile")

            add_message(
                catalog,
                f"profile.{pslug}.section",
                section,
                location=(str(bf), 1),
                comment_prefix=f"Profile section title ({section})",
            )
            add_message(
                catalog,
                f"profile.{pslug}.description",
                desc,
                location=(str(bf), 1),
                comment_prefix=f"Profile description ({section})",
            )

            rules = _safe_get(prof, "rules", []) or []
            for rule in rules:
                rid = _safe_get(rule, "rule_id", None)
                if not rid:
                    continue

                rtitle = _safe_get(rule, "title", "")
                rdisc = _safe_get(rule, "discussion", "")

                add_message(
                    catalog,
                    f"rule.{rid}.title",
                    rtitle,
                    location=(str(bf), 1),
                    comment_prefix=f"Rule title ({rid})",
                )
                add_message(
                    catalog,
                    f"rule.{rid}.discussion",
                    rdisc,
                    location=(str(bf), 1),
                    comment_prefix=f"Rule discussion ({rid})",
                )

    out_path = Path(args.output).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        write_po(f, catalog, width=100, omit_header=False)

    print(f"Wrote POT with {len(catalog)} messages to: {out_path}")
