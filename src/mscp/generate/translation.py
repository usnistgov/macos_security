# mscp/generate/translation.py

import argparse
from pathlib import Path

from babel.messages.catalog import Catalog
from babel.messages.pofile import write_po

from ..classes import Macsecurityrule
from ..common_utils import config, open_file


def generate_translation(args: argparse.Namespace) -> None:
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

    output_path = Path(config["output_dir"])
    output_path.mkdir(parents=True, exist_ok=True)
    output_file = output_path / args.output
    with output_file.open("wb") as f:
        write_po(f, catalog, width=100, omit_header=False)

    print(
        f"Generated translation template file with {len(catalog)} messages to: {output_file}"
    )
