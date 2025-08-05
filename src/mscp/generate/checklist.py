# mscp/generate/checklist.py

# Standard python modules
import argparse
import platform
import re
import sys
import zipfile
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

# Additional python modules
from jinja2 import Environment, FileSystemLoader
from lxml.etree import Element, XMLParser, fromstring

# Local python modules
from ..classes import Baseline
from ..common_utils import config, create_file, create_json, logger, open_file

XML_PARSER: XMLParser = XMLParser(recover=True, ns_clean=True, encoding="utf-8")


@logger.catch
def extract_manual_xml(zip_path: Path) -> Element:
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for file_name in zip_ref.namelist():
            if "Manual" in file_name and file_name.endswith(".xml"):
                with zip_ref.open(file_name) as xml_file:
                    xml_content = xml_file.read().decode("utf-8")
                    xml_content = (
                        xml_content.replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .encode("utf-8")
                    )
                    return fromstring(xml_content, parser=XML_PARSER)
    logger.error("No manual XML file found in the zip archive.")
    raise FileNotFoundError("No manual XML file found in the zip archive.")


def xml_to_dict(element: Element) -> dict[str, Any]:
    def _element_to_dict(elem: Element) -> dict:
        tag = re.sub(
            r"\{.*\}", "", elem.tag
        ).lower()  # Remove namespace and convert to lower case
        d = OrderedDict({tag: {} if elem.attrib else None})
        children = list(elem)
        if children:
            dd = defaultdict(list)
            for dc in map(_element_to_dict, children):
                for k, v in dc.items():
                    k = re.sub(r"\{.*\}", "", k).lower()  # Convert to lower case
                    dd[k].append(v)
            d = OrderedDict(
                {tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
            )
        if elem.attrib:
            d[tag].update(
                (k.lower(), v) for k, v in elem.attrib.items()
            )  # Convert to lower case
        if elem.text:
            text = elem.text.strip()
            if children or elem.attrib:
                if text:
                    d[tag]["text"] = text
            else:
                d[tag] = text
        return d

    return _element_to_dict(element)


@logger.catch
def map_stig_data(
    stig_data: dict[str, Any],
    baseline: Baseline,
    stig_uuid: str,
    created: str,
    updated: str,
) -> list[dict[str, Any]]:
    rule_list: list[dict[str, Any]] = []

    for group in stig_data["benchmark"]["group"]:
        logger.debug(f"Processing group: {group['id']}")
        ccis_list: list[str] = []

        for key, value in group["rule"]["description"].items():
            if value is None:
                group["rule"]["description"][key] = ""

        matching_rule = next(
            (
                r
                for profile in baseline.profile
                for r in profile.rules
                if group["rule"]["version"] in r.references.disa_stig
            ),
            None,
        )

        if isinstance(group["rule"]["ident"], dict):
            ccis_list.append(group["rule"]["ident"]["text"])

        if isinstance(group["rule"]["ident"], list):
            ccis_list = [ident["text"] for ident in group["rule"]["ident"]]

        rule_result = {
            "uuid": str(uuid4()),
            "stig_uuid": stig_uuid,
            "target_key": None,
            "stig_ref": None,
            "group_id": group["id"],
            "rule_id": group["rule"]["id"].replace("_rule", ""),
            "rule_id_src": group["rule"]["id"],
            "weight": group["rule"]["weight"],
            "classification": "Unclassified",
            "severity": group["rule"]["severity"],
            "rule_version": group["rule"]["version"],
            "group_title": group["title"],
            "rule_title": group["rule"]["title"],
            "fix_text": group["rule"]["fixtext"]["text"],
            "false_positives": (
                ""
                if group["rule"]["description"]["falsepositives"] == ""
                else group["rule"]["description"]["falsepositives"]
            ),
            "false_negatives": (
                ""
                if group["rule"]["description"]["falsenegatives"] == ""
                else group["rule"]["description"]["falsenegatives"]
            ),
            "discussion": group["rule"]["description"]["vulndiscussion"],
            "check_content": group["rule"]["check"]["check-content"],
            "documentable": (
                ""
                if group["rule"]["description"]["documentable"] == ""
                else group["rule"]["description"]["documentable"]
            ),
            "mitigations": (
                ""
                if group["rule"]["description"]["mitigations"] == ""
                else group["rule"]["description"]["mitigations"]
            ),
            "potential_impacts": (
                ""
                if group["rule"]["description"]["potentialimpacts"] == ""
                else group["rule"]["description"]["potentialimpacts"]
            ),
            "third_party_tools": (
                ""
                if group["rule"]["description"]["thirdpartytools"] == ""
                else group["rule"]["description"]["thirdpartytools"]
            ),
            "mitigation_control": (
                ""
                if group["rule"]["description"]["mitigationcontrol"] == ""
                else group["rule"]["description"]["mitigationcontrol"]
            ),
            "responsibility": (
                ""
                if group["rule"]["description"]["responsibility"] == ""
                else group["rule"]["description"]["responsibility"]
            ),
            "security_override_guidance": (
                ""
                if group["rule"]["description"]["severityoverrideguidance"] == ""
                else group["rule"]["description"]["severityoverrideguidance"]
            ),
            "ia_controls": (
                ""
                if group["rule"]["description"]["iacontrols"] == ""
                else group["rule"]["description"]["iacontrols"]
            ),
            "check_content_ref": {
                "href": group["rule"]["check"]["check-content-ref"]["href"],
                "name": group["rule"]["check"]["check-content-ref"]["name"],
            },
            "legacy_ids": [],
            "ccis": ccis_list,
            "group_tree": [
                {
                    "id": group["id"],
                    "title": group["title"],
                    "description": (
                        "<GroupDescription></GroupDescription>"
                        if group["description"]["groupdescription"] is None
                        else group["description"]["groupdescription"]
                    ),
                }
            ],
            "createdAt": created,
            "updatedAt": updated,
            "STIGUuid": stig_uuid,
            "status": "not_a_finding" if not matching_rule.finding else "open",
            "overrides": {},
            "comments": "",
            "finding_details": "",
        }
        rule_list.append(rule_result)

    return sorted(rule_list, key=lambda x: x["rule_version"])


@logger.catch
def generate_checklist_v2(
    output_file: Path,
    stig_data: dict[str, Any],
    stig_filename: str,
    stig_description: str,
) -> None:
    env: Environment = Environment(
        loader=FileSystemLoader(f"{config['defaults']['templates_dir']}/checklist")
    )
    template = env.get_template("checklist.xml.jinja")
    stig_data["filename"] = stig_filename

    create_file(
        output_file,
        template.render(
            stig_data=stig_data,
            stig_filename=stig_filename,
            stig_description=stig_description,
        ),
    )


def generate_checklist(args: argparse.Namespace) -> None:
    create_date: str = str(datetime.today().date())
    output_file: Path = Path(
        config["output_dir"],
        f"Apple_{args.os_name}_{args.os_version}-STIG-Checklist-{create_date}.chlk",
    )
    default_baseline: Path = Path(
        config["defaults"]["baseline_dir"],
        args.os_name,
        str(args.os_version),
        "DISA-STIG.yaml",
    )
    checklist_created_date: str = (
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )
    checklist_updated_date: str = checklist_created_date
    stig_data: dict[str, Any] = {}
    stig_uuid: str = str(uuid4())

    if not args.plist:
        logger.error("No plist supplied.")
        sys.exit()

    if not args.disastig:
        logger.error("No DISA STIG file provided")
        sys.exit()

    if "DISA-STIG" not in args.plist.name:
        logger.error("Wrong plist supplied, must be the DISA STIG checklist")
        sys.exit()

    if args.baseline:
        custom: bool = True if "custom" in args.baseline else False
        baseline: Baseline = Baseline.from_yaml(
            args.baseline, args.os_name, args.os_version, custom
        )
    else:
        baseline: Baseline = Baseline.from_yaml(
            default_baseline, args.os_name, args.os_version
        )

    logger.debug(f"Plist File: {args.plist}")
    logger.debug(f"Stig File: {args.disastig}")

    plist_data: dict[str, dict[str, Any]] = open_file(args.plist)

    if ".zip" in args.disastig.suffix:
        stig_data = extract_manual_xml(args.disastig)
    else:
        xml_raw: bytes = (
            args.disastig.read_text(encoding="utf-8")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .encode("utf-8")
        )
        stig_data_raw: Element = fromstring(xml_raw, parser=XML_PARSER)

    stig_data = xml_to_dict(stig_data_raw)

    for profile in baseline.profile:
        for rule in profile.rules:
            if rule.rule_id in plist_data:
                rule.finding = plist_data[rule.rule_id].get("finding", False)

    num_rules = sum(len(profile.rules) for profile in baseline.profile)

    logger.debug(f"Number of rules in the baseline profile: {num_rules}")

    stig_output_dict: dict[str, Any] = {
        "title": output_file.stem,
        "id": str(uuid4()),
        "cklb_version": "1.0",
        "has_path": False,
        "active": True,
        "mode": 2,
        "target_data": {
            "target_type": "Computing",
            "host_name": platform.node(),
            "ip_address": "",
            "mac_address": "",
            "fqdn": "",
            "comments": "",
            "role": "None",
            "is_web_database": False,
            "technology_area": "",
            "web_db_site": "",
            "web_db_instance": "",
            "classification": "",
        },
        "stigs": [
            {
                "stig_name": stig_data["benchmark"]["title"],
                "display_name": stig_data["benchmark"]["title"]
                .replace("Security Technical Implementation Guide", "")
                .strip(),
                "stig_id": stig_data["benchmark"]["id"],
                "release_info": next(
                    (
                        item["text"]
                        for item in stig_data["benchmark"]["plain-text"]
                        if item["id"] == "release-info"
                    ),
                    "",
                ),
                "version": stig_data["benchmark"]["version"],
                "uuid": stig_uuid,
                "reference_identifier": "5661",
                "size": num_rules,
                "rules": [],
            }
        ],
    }

    stig_output_dict["stigs"][0]["rules"] = map_stig_data(
        stig_data, baseline, stig_uuid, checklist_created_date, checklist_updated_date
    )

    if args.version == "3":
        create_json(output_file, stig_output_dict)
    else:
        output_file.replace(output_file.with_suffix(".ckl"))
        generate_checklist_v2(
            output_file, stig_output_dict, args.disastig.name, baseline.description
        )

    # output_file.write_text(json.dumps(stig_output_dict, indent=2))
    logger.info(f"Checklist generated and saved to {output_file}")
