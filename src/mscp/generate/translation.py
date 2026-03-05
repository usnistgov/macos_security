# mscp/generate/translation.py

import argparse
import json
from pathlib import Path
import re

from babel.messages.catalog import Catalog
from babel.messages import pofile, mofile

from ..classes import Macsecurityrule
from ..common_utils import config, open_file


def extract_trans_text(template: str) -> list[str]:
    """
    Extracts the text within {% trans %} and {% endtrans %} blocks.

    Args:
        template (str): String value containing text to extract.

    Returns:
        [str]: A list of extracted strings
    """
    pattern = r"{%\s*trans\b.*?%}(.*?){%\s*endtrans\s*%}"
    chunks = re.findall(pattern, template, flags=re.S)

    cleaned = set()
    for chunk in chunks:
        # 2) Remove any {{ ... }} template expressions
        chunk = re.sub(r"{{.*?}}", "", chunk, flags=re.S)
        # 3) Remove leading table pipe markers on each line
        chunk = re.sub(r"(?m)^\s*\|\s*", "", chunk)
        # 4) Normalize whitespace
        chunk = chunk.strip()
        cleaned.add(chunk)

    # Optionally, drop empty results (if any)
    return [c for c in cleaned if c]


def generate_localize_template(args: argparse.Namespace) -> None:
    """
    Generates a translation template file used for localization.

    Args:
        args (argparse.Namespace): Command-line arguments containing options for generating the report.

    This function creates a babel catalog to collect translation information.

    It will parse all of the yaml files in /config/default/sections and add strings to translate
    from the name and description fields to the catalog.

    It will also parse all of the yaml files in /config/default/rules and add strings to translate
    from the title and discussion fields to the catalog.

    It will then output the messages.pot file from the contents of the catalog.

    """

    catalog = Catalog(
        domain=args.domain,
        project="macOS Security Compliance Project",
        charset="utf-8",
    )

    # collect name and description from all section files
    for yaml_file in Path(config["defaults"]["sections_dir"]).glob("*.y*ml"):
        section_data: dict = open_file(yaml_file)
        catalog.add(
            id=section_data["name"],
            string=None,
            locations=[],
            context=f"section.{yaml_file.stem}.name",
        )
        catalog.add(
            id=section_data["description"],
            string=None,
            locations=[],
            context=f"section.{yaml_file.stem}.description",
        )

    # collect name and description from all template files
    for template_file in Path(config["defaults"]["templates_dir"]).rglob("*.jinja"):
        template_data: str = open_file(template_file)
        strings_to_include = extract_trans_text(template_data)
        ctr = 0
        for string in strings_to_include:
            ctr += 1
            catalog.add(
                id=string,
                string=None,
                locations=[],
                context=f"template.{template_file.stem}.{ctr}",
            )

    rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version, tailoring=True
    )

    # collect title and discussion from all rule data
    for rule in rules:
        catalog.add(
            id=rule.title,
            string=None,
            locations=[],
            context=f"rule.{rule.rule_id}.title",
        )
        catalog.add(
            id=rule.discussion,
            string=None,
            locations=[],
            context=f"rule.{rule.rule_id}.discussion",
        )

    messages = {}
    for message in catalog:
        if message.context:
            messages[message.context] = message.id

    output_path = Path(config["output_dir"])
    output_path.mkdir(parents=True, exist_ok=True)

    json_output_file = output_path / args.output
    with open(json_output_file, "w", encoding="utf-8") as json_file:
        json.dump(messages, json_file, indent=4, ensure_ascii=False)

    print(f"Generated json file with {len(catalog)} messages to: {json_output_file}")


def generate_mo_from_json(args: argparse.Namespace) -> None:
    """
    Compile a translated .json file to a .mo file using Babel.

    Args:
        args (argparse.Namespace): Command-line arguments containing options for generating the report.
    """
    json_file = Path(args.json_file)
    with json_file.open("rb") as fp:
        translations = json.load(fp)

    catalog = Catalog(
        domain=args.domain,
        project="macOS Security Compliance Project",
        charset="utf-8",
        locale=args.locale,
    )

    for message in translations:
        catalog.add(
            id=translations[message]["en"],
            string=translations[message][args.locale],
            locations=[],
        )

    output_path = (
        Path(config["output_dir"]) / "locale" / f"{args.locale}" / "LC_MESSAGES"
    )
    output_path.mkdir(parents=True, exist_ok=True)
    mo_output_file = output_path / args.mo_file

    with mo_output_file.open("wb") as out_fp:
        mofile.write_mo(out_fp, catalog, use_fuzzy=args.use_fuzzy)

    po_output_file = output_path / "messages.po"
    with po_output_file.open("wb") as f:
        pofile.write_po(f, catalog, width=100, omit_header=False)

    print(
        f"Generated '{catalog.locale}' localization file with {len(catalog)} messages to: {mo_output_file}"
    )
