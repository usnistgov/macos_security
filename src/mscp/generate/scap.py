# mscp/generate/scap.py

# Standard python modules
import argparse
import sys
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape
from xml.dom import minidom


# Additional python modules

# Local python modules
from ..classes import Macsecurityrule
from ..common_utils import config, get_version_data, logger, mscp_data

from .baseline import (
    print_keyword_summary,
    collect_tags_and_benchmarks,
    rule_has_benchmark_for_version,
)


def pretty_format_xml(xml_string: str) -> str:
    """Format XML using minidom, without extra blank lines."""
    parsed = minidom.parseString(xml_string)
    pretty_xml_as_string = parsed.toprettyxml(indent="  ")
    return "\n".join(
        [line for line in pretty_xml_as_string.split("\n") if line.strip()]
    )


def generate_scap(args: argparse.Namespace) -> None:
    # logger.error("generate_scap() NEEDS TO BE BUILT")

    output_file: Path = Path(config["output_dir"])

    if args.list_tags:
        all_rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
            args.os_name, args.os_version
        )
        all_tags, benchmark_map = collect_tags_and_benchmarks(all_rules)
        print_keyword_summary(all_tags, benchmark_map)
        sys.exit()

    current_version_data: dict = get_version_data(
        args.os_name, args.os_version, mscp_data
    )

    def replace_vars(text: str) -> str:
        os_list = (
            mscp_data.get("versions", {}).get("platforms", {}).get(args.os_name, [])
        )

        for entry in os_list:
            if entry.get("os_version") == args.os_version:
                os_name = entry.get("os_name").capitalize()

        match args.os_name:
            case "macos":
                clean_text = (
                    text.replace("$os_type", "macOS")
                    .replace("$os_version", str(args.os_version))
                    .replace("$os_name", os_name)
                )
            case "ios":
                clean_text = (
                    text.replace("($os_name) ", "")
                    .replace("$os_type", "iOS/iPadOS")
                    .replace("$os_version", str(args.os_version))
                )
            case "visionos":
                clean_text = text.replace("$os_type", "visionOS").replace(
                    "$os_version", str(args.os_version)
                )

        return clean_text

    all_rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version, generate_baseline=False
    )

    all_tags, benchmark_map = collect_tags_and_benchmarks(all_rules)
    all_baseline_benchmark = []
    if args.baseline is None:
        args.baseline = "all_rules"
    if args.baseline == "all_rules":
        for k, v in benchmark_map.items():
            if list(v)[0].lower() == args.os_name.lower():
                all_baseline_benchmark.append(k)

        for v in all_tags:
            if (
                v == "n_a"
                or v == "inherent"
                or v == "manual"
                or v == "none"
                or v == "permanent"
                or v == "supplemental"
                or v == "i386"
                or v == "arm64"
                or v == "srg"
            ):
                continue
            all_baseline_benchmark.append(v)
    else:
        all_baseline_benchmark = [args.baseline]

    all_the_baselines = [{}]
    for b in all_baseline_benchmark:
        found_rules = [
            rule
            for rule in all_rules
            if rule_has_benchmark_for_version(
                rule, b, args.os_name, str(args.os_version)
            )
            or (rule.tags is not None and b in rule.tags)
        ]
        baseline_dict = {b: found_rules}
        all_the_baselines.append(baseline_dict)

    xccdfProfiles = str()
    oval_def = str()
    oval_tests = str()
    oval_objects = str()
    oval_states = str()
    oval_counter = 1

    for baseline in all_the_baselines:
        for b, r in baseline.items():
            xccdfrules = str()
            xccdfProfiles = (
                xccdfProfiles
                + """<Profile id="xccdf_gov.nist.mscp.content_profile_{0}"><title>{0}</title><description>This profile selects all rules tagged as {0}.</description>""".format(
                    b
                )
            )
            for rule in r:
                odv_tag = "recommended"

                try:
                    if b in rule["odv"]:
                        odv_tag = b
                except (TypeError, KeyError) as e:
                    logger.warning(f"Error when looking up ODV for {rule.rule_id}: {e}")

                rule._fill_in_odv(b)

                xccdfProfiles = (
                    xccdfProfiles
                    + """<select idref="xccdf_gov.nist.mscp.content_rule_{0}_{1}" selected="true"/>""".format(
                        rule["rule_id"], odv_tag
                    )
                )

            xccdfProfiles = xccdfProfiles + "</Profile>"

    for rule in all_rules:
        if args.baseline != "all_rules":
            if (
                not rule_has_benchmark_for_version(
                    rule, args.baseline, args.os_name, str(args.os_version)
                )
                and args.baseline not in rule.tags
            ):
                continue

        xccdf_references = str()
        separator = ", "

        try:
            if len(rule["references"].nist.nist_800_53r5) > 0:
                xccdf_references = (
                    xccdf_references
                    + """<reference href="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final">NIST SP 800-53r5: {0}</reference>""".format(
                        separator.join(rule["references"].nist.nist_800_53r5)
                    )
                )
        except (TypeError, KeyError, AttributeError) as e:
            logger.warning(
                f"Error when trying to build 800-53r5 references for {rule.rule_id}: {e}"
            )

        try:
            if len(rule["references"].nist.nist_800_171r3) > 0:
                xccdf_references = (
                    xccdf_references
                    + """<reference href="https://csrc.nist.gov/pubs/sp/800/171/r3/final">NIST SP 800-171r3: {0}</reference>""".format(
                        separator.join(rule["references"].nist.nist_800_171r3)
                    )
                )
        except (TypeError, KeyError, AttributeError) as e:
            logger.warning(
                f"Error when trying to build 800-171r3 references for {rule.rule_id}: {e}"
            )

        try:
            if len(rule["references"].disa.disa_stig) > 0:
                xccdf_references = (
                    xccdf_references
                    + """<reference href="https://www.cyber.mil/stigs/downloads/">DISA STIG(s): {0}</reference>""".format(
                        separator.join(rule["references"].disa.disa_stig)
                    )
                )
        except (TypeError, KeyError, AttributeError) as e:
            logger.warning(
                f"Error when trying to build DISA STIG references for {rule.rule_id}: {e}"
            )

        try:
            if len(rule["references"].cis.benchmark) > 0:
                xccdf_references = (
                    xccdf_references
                    + """<reference href="https://www.cisecurity.org/cis-benchmarks/">CIS Benchmark: {0}</reference>""".format(
                        separator.join(rule["references"].cis.benchmark)
                    )
                )
        except (TypeError, KeyError, AttributeError) as e:
            logger.warning(
                f"Error when trying to build CIS benchmark references for {rule.rule_id}: {e}"
            )

        try:
            if len(rule["references"].cis.controls_v8) > 0:
                cisv8 = str()
                for cis_ref in rule["references"].cis.controls_v8:
                    cisv8 = cisv8 + "{}, ".format(cis_ref)
                xccdf_references = (
                    xccdf_references
                    + """<reference href="https://www.cisecurity.org/controls">CIS Controls V8: {0}</reference>""".format(
                        cisv8[0:-2]
                    )
                )
        except (TypeError, KeyError, AttributeError) as e:
            logger.warning(
                f"Error when trying to build CIS Controls references for {rule.rule_id}: {e}"
            )

        selected_os_benchmark = []
        for benchmark, v in benchmark_map.items():
            if list(v)[0].lower() == args.os_name.lower():
                if args.baseline != "all_rules":
                    if benchmark == args.baseline:
                        selected_os_benchmark.append(benchmark)
                else:
                    selected_os_benchmark.append(benchmark)

        if rule.odv is not None:
            if args.baseline == "all_rules":
                selected_os_benchmark.append("recommended")
            for k, _ in rule.odv.items():
                if k == "hint":
                    continue
                if k in selected_os_benchmark:
                    check_content = str()
                    if args.xccdf is None and args.oval is None:
                        check_content = """<check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"><check-content-ref href="oval.xml" name="oval:mscp:def:{}"/></check>""".format(
                            oval_counter
                        )
                    rule._fill_in_odv(k)
                    fix_value = "none" if rule.fix is None else escape(rule.fix)
                    check_value = "none" if rule.check is None else escape(rule.check)
                    count_found = False
                    check_existence = "all_exist"
                    if " 2> /dev/null" in check_value:
                        check_value = check_value.replace(" 2> /dev/null", "")

                    if "/usr/bin/grep -c" in check_value:
                        if (
                            'echo "1"' not in check_value
                            or 'echo "0"' not in check_value
                        ):
                            if "/usr/bin/ssh -G ." not in check_value:
                                if "auditd_enabled" not in check_value:
                                    if "/usr/sbin/sshd -G" not in check_value:
                                        check_value = check_value.replace(
                                            "/usr/bin/grep -c ", "/usr/bin/grep "
                                        )
                                        count_found = True
                                        if rule.result_value == 0:
                                            check_existence = "none_exist"

                    if "launchctl list" in check_value:
                        check_value = check_value.replace(
                            "launchctl list", "launchctl print system"
                        )
                        if "auditd_enabled" in check_value:
                            check_value = check_value.replace(
                                "/usr/bin/grep -c com.apple.auditd",
                                "/usr/bin/grep -c '\"com.apple.auditd\" => enabled'",
                            )

                    if "/usr/bin/wc -l" in check_value:
                        new_test = []
                        for command in check_value.split("|"):
                            if "/usr/bin/wc -l" in command:
                                break
                            new_test.append(command.strip())
                        count_found = True

                        check_value = "|".join(new_test)
                        if rule.result_value == 0:
                            check_existence = "none_exist"

                    if "$CURRENT_USER" in check_value:
                        check_value = """CURRENT_USER=$(/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow.plist lastUserName)
{}""".format(check_value)

                    xccdfrules = (
                        xccdfrules
                        + """<Rule id="xccdf_gov.nist.mscp.content_rule_{0}_{1}" selected="false" role="full" severity="{2}" weight="1.0"><title>{3}</title><description>{4}
                {5}

                Expected Result: {6}
                </description>{7}<ident system="https://ncp.nist.gov/cce">{8}</ident><fixtext>        {9}
                </fixtext>{10}
                </Rule>""".format(
                            rule["rule_id"],
                            k,
                            rule.severity,
                            rule["title"],
                            escape(rule["discussion"]),
                            check_value,
                            rule.result_value,
                            xccdf_references,
                            rule["references"].nist.cce,
                            fix_value,
                            check_content,
                        )
                    )

                if args.os_name == "macos":
                    oval_def = (
                        oval_def
                        + """<definition id="oval:mscp:def:{0}" version="1" class="compliance"><metadata><title>{1}</title><reference source="CCE" ref_id="{2}"/><reference source="macos_security" ref_id="{3}_{4}"/><description>{5}</description></metadata><criteria><criterion comment="{3}_{4}" test_ref="oval:mscp:tst:{0}"/></criteria></definition>""".format(
                            oval_counter,
                            rule["title"],
                            rule["references"].nist.cce,
                            rule["rule_id"],
                            k,
                            escape(rule["discussion"]),
                        )
                    )

                    oval_tests = (
                        oval_tests
                        + """<shellcommand_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:tst:{0}" version="1" comment="{1}_{2}_test" check_existence="{3}" check="all"><object object_ref="oval:mscp:obj:{0}"/><state state_ref="oval:mscp:ste:{0}"/></shellcommand_test>""".format(
                            oval_counter, rule.rule_id, k, check_existence
                        )
                    )

                    oval_objects = (
                        oval_objects
                        + """<shellcommand_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:obj:{0}" version="1" comment="{1}_{2}_object"><shell>zsh</shell><command>{3}</command></shellcommand_object>""".format(
                            oval_counter, rule.rule_id, k, check_value
                        )
                    )

                    if count_found:
                        if check_existence != "none_exist":
                            oval_states = (
                                oval_states
                                + """<shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_{2}_state"><stdout_line operation="pattern match">.*</stdout_line></shellcommand_state>""".format(
                                    oval_counter, rule.rule_id, k
                                )
                            )
                        else:
                            oval_states = (
                                oval_states
                                + """<shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_{2}_state"><stdout_line check_existence="none_exist" /></shellcommand_state>""".format(
                                    oval_counter, rule.rule_id, k
                                )
                            )

                    else:
                        oval_states = (
                            oval_states
                            + """<shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_{2}state"><stdout_line operation="equals">{3}</stdout_line></shellcommand_state>""".format(
                                oval_counter, rule.rule_id, k, rule.result_value
                            )
                        )

        else:
            fix_value = "none" if rule.fix is None else escape(rule.fix)
            check_value = "none" if rule.check is None else escape(rule.check)
            check_existence = "all_exist"
            count_found = False
            check_content = str()
            if args.xccdf is None and args.oval is None:
                check_content = """<check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"><check-content-ref href="oval.xml" name="oval:mscp:def:{}"/></check>""".format(
                    oval_counter
                )

                if "manual" in rule.tags:
                    check_content = """<check system="http://scap.nist.gov/schema/ocil/2"><check-content-ref href="ocil.xml"/></check>"""
            if "$CURRENT_USER" in check_value:
                check_value = """CURRENT_USER=$(/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow.plist lastUserName)
{}""".format(check_value)

            if " 2> /dev/null" in check_value:
                check_value = check_value.replace(" 2> /dev/null", "")

            if "/usr/bin/grep -c" in check_value:
                if 'echo "1"' not in check_value or 'echo "0"' not in check_value:
                    if "/usr/bin/ssh -G ." not in check_value:
                        if "auditd_enabled" not in check_value:
                            if "/usr/sbin/sshd -G" not in check_value:
                                check_value = check_value.replace(
                                    "/usr/bin/grep -c ", "/usr/bin/grep "
                                )
                                count_found = True
                                if rule.result_value == 0:
                                    check_existence = "none_exist"

            if "launchctl list" in check_value:
                check_value = check_value.replace(
                    "launchctl list", "launchctl print system"
                )
                if "auditd_enabled" in check_value:
                    check_value = check_value.replace(
                        "/usr/bin/grep -c com.apple.auditd",
                        "/usr/bin/grep -c '\"com.apple.auditd\" => enabled'",
                    )

            if "/usr/bin/wc -l" in check_value:
                new_test = []
                for command in check_value.split("|"):
                    if "/usr/bin/wc -l" in command:
                        break
                    new_test.append(command.strip())
                count_found = True

                check_value = "|".join(new_test)
                if rule.result_value == 0:
                    check_existence = "none_exist"

            xccdfrules = (
                xccdfrules
                + """<Rule id="xccdf_gov.nist.mscp.content_rule_{0}_{1}" selected="false" role="full" severity="{2}" weight="1.0"><title>{3}</title><description>{4}
                {5}
                Expected Result: {6}
                </description>{7}<ident system="https://ncp.nist.gov/cce">{8}</ident><fixtext>{9}</fixtext>{10}</Rule>""".format(
                    rule["rule_id"],
                    "recommended",
                    rule.severity,
                    rule["title"],
                    escape(rule["discussion"]),
                    check_value,
                    rule.result_value,
                    xccdf_references,
                    rule["references"].nist.cce,
                    fix_value,
                    check_content,
                )
            )

            if args.os_name == "macos":
                oval_def = (
                    oval_def
                    + """<definition id="oval:mscp:def:{0}" version="1" class="compliance"><metadata><title>{1}</title><reference source="CCE" ref_id="{2}"/><reference source="macos_security" ref_id="{3}_{4}"/><description>{5}</description></metadata><criteria><criterion comment="{3}_{4}" test_ref="oval:mscp:tst:{0}"/></criteria></definition>""".format(
                        oval_counter,
                        rule["title"],
                        rule["references"].nist.cce,
                        rule["rule_id"],
                        "recommended",
                        escape(rule["discussion"]),
                    )
                )

                oval_tests = (
                    oval_tests
                    + """<shellcommand_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:tst:{0}" version="1" comment="{1}_{2}_test" check_existence="{3}" check="all"><object object_ref="oval:mscp:obj:{0}"/><state state_ref="oval:mscp:ste:{0}"/></shellcommand_test>""".format(
                        oval_counter, rule.rule_id, "recommended", check_existence
                    )
                )

                oval_objects = (
                    oval_objects
                    + """<shellcommand_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:obj:{0}" version="1" comment="{1}_{2}_object"><shell>zsh</shell><command>{3}</command></shellcommand_object>""".format(
                        oval_counter, rule.rule_id, "recommended", check_value
                    )
                )

                if count_found:
                    if check_existence != "none_exist":
                        oval_states = (
                            oval_states
                            + """<shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_{2}_state"><stdout_line operation="pattern match">.*</stdout_line></shellcommand_state>""".format(
                                oval_counter, rule.rule_id, "recommended"
                            )
                        )
                    else:
                        oval_states = (
                            oval_states
                            + """<shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_{2}_state"><stdout_line check_existence="none_exist" /></shellcommand_state>""".format(
                                oval_counter, rule.rule_id, "recommended"
                            )
                        )

                else:
                    oval_states = (
                        oval_states
                        + """<shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_{2}state"><stdout_line operation="equals">{3}</stdout_line></shellcommand_state>""".format(
                            oval_counter, rule.rule_id, "recommended", rule.result_value
                        )
                    )

        oval_counter += 1

    now = datetime.now()
    date_time_string = now.strftime("%Y-%m-%dT%H:%M:%S")

    xccdf = """<?xml version="1.0" encoding="UTF-8"?>"""
    xccdfPrefix = """<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_gov.nist.mscp.content_benchmark_{1}_{2}" style="SCAP_1.4" resolved="true" xml:lang="en"><status date="{3}">draft</status><title>{1} {2}: Security Configuration</title><description>{1} {2}: Security Configuration</description><reference href="https://csrc.nist.gov/projects/security-content-automation-protocol/scap-releases/scap-1-3"><title xmlns="http://purl.org/dc/elements/1.1/">Security Content Automation Protocol</title><publisher xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</publisher></reference><version time="{0}" update="https://github.com/usnistgov/macos_security">{4}</version><metadata><creator xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</creator><publisher xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</publisher><source xmlns="http://purl.org/dc/elements/1.1/">https://github.com/usnistgov/macos_security/releases/latest</source><contributor xmlns="http://purl.org/dc/elements/1.1/">Bob Gendler - National Institute of Standards and Technology</contributor><contributor xmlns="http://purl.org/dc/elements/1.1/">Dan Brodjieski - National Aeronautics and Space Administration</contributor><contributor xmlns="http://purl.org/dc/elements/1.1/">Allen Golbig - Jamf</contributor></metadata>""".format(
        date_time_string,
        current_version_data["os_name"],
        current_version_data["os_version"],
        date_time_string.split("T")[0] + "Z",
        current_version_data["compliance_version"],
    )

    xccdf_group = """<Group id="xccdf_gov.nist.mscp.content_group_all_rules"><title>All rules</title><description>All the rules</description><warning category="general">The check/fix commands outlined in this section must be run with elevated privileges.</warning>"""

    xccdf_closer = """</Group></Benchmark>"""

    oval = """<?xml version="1.0" encoding="UTF-8"?>"""

    oval_prefix = """<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5 https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#macos https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/macos-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/unix-definitions-schema.xsd"><generator><oval:schema_version>5.12.1</oval:schema_version><oval:timestamp xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">{}</oval:timestamp><terms_of_use>Copyright (c) 2025, NIST.</terms_of_use><oval:product_name xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">macOS Security Compliance Project</oval:product_name></generator>""".format(
        date_time_string
    )

    oval_def = "<definitions>" + oval_def + "</definitions>"

    oval_tests = "<tests>" + oval_tests + "</tests>"

    oval_objects = "<objects>" + oval_objects + "</objects>"

    oval_states = "<states>" + oval_states + "</states>"

    if args.oval is None and args.xccdf is None and args.os_name == "macos":
        scap = """<?xml version="1.0" encoding="UTF-8"?><data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2" id="scap_gov.nist.mscp.content_collection_macOS_{0}.0" schematron-version="1.4"><data-stream timestamp="{1}" id="scap_gov.nist.mscp.content_datastream_macOS_{0}.0" scap-version="1.4" use-case="CONFIGURATION"><dictionaries><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_macOS-cpe-dictionary.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_macOS-cpe-dictionary.xml"><catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">  <uri name="macOS-cpe-oval.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{0}_macOS-cpe-oval.xml"/></catalog></component-ref></dictionaries><checklists><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_xccdf.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_xccdf.xml"><catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">  <uri name="oval.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{0}_check_1"/>  <uri name="ocil.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{0}_check_2"/></catalog></component-ref></checklists><checks><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_macOS-cpe-oval.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_macOS-cpe-oval.xml"/><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_check_1" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_check_1"/><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_check_2" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_check_2"/></checks></data-stream>""".format(
            current_version_data["os_version"], date_time_string
        )

        xccdf = (
            '<component id="scap_gov.nist.mscp.content_comp_macOS_{0}_xccdf.xml" timestamp="{1}">'.format(
                current_version_data["os_version"], date_time_string
            )
            + xccdfPrefix
            + xccdfProfiles
            + xccdf_group
            + xccdfrules
            + xccdf_closer
            + "</component>"
        )

        oval = (
            '<component id="scap_gov.nist.mscp.content_comp_macOS_{0}_check_1" timestamp="{1}">'.format(
                current_version_data["os_version"], date_time_string
            )
            + oval_prefix
            + oval_def
            + oval_tests
            + oval_objects
            + oval_states
            + "</oval_definitions></component>"
        )

        ocil = """<component id="scap_gov.nist.mscp.content_comp_macOS_{0}_check_2" timestamp="2025-11-05T10:30:43"><ocil xmlns="http://scap.nist.gov/schema/ocil/2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://scap.nist.gov/schema/ocil/2.0 ocil-2.0.xsd"><generator><product_name>Manual Labor</product_name><product_version>1</product_version><schema_version>2.0</schema_version><timestamp>{0}</timestamp></generator><questionnaires><questionnaire id="ocil:gov.nist.mscp.content:questionnaire:1">  <title>Obtain a pass or a fail</title>  <actions>    <test_action_ref>ocil:gov.nist.mscp.content:testaction:1</test_action_ref>  </actions></questionnaire></questionnaires><test_actions><boolean_question_test_action id="ocil:gov.nist.mscp.content:testaction:1" question_ref="ocil:gov.nist.mscp.content:question:1">  <when_true>    <result>PASS</result>  </when_true>  <when_false>    <result>FAIL</result>  </when_false></boolean_question_test_action></test_actions><questions><boolean_question id="ocil:gov.nist.mscp.content:question:1">  <question_text>Do you wish this checklist item to be considered to have passed?</question_text></boolean_question></questions></ocil></component>""".format(
            date_time_string
        )

        cpe = """<component id="scap_gov.nist.mscp.content_comp_macOS_{0}_macOS-cpe-dictionary.xml" timestamp="{1}"><?xml-model href="https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd" schematypens="http://www.w3.org/2001/XMLSchema" title="CPE XML schema"?><cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0" xmlns:cpe-23="http://scap.nist.gov/schema/cpe-extension/2.3"><generator><product_name>macOS Security Compliance Project</product_name><schema_version>2.3</schema_version><timestamp>{1}</timestamp></generator><cpe-item name="cpe:/{2}"><title xml:lang="en-US">Apple macOS {0}</title><notes xml:lang="en-US">  <note>This CPE Name represents macOS {0}</note></notes><check href="macOS-cpe-oval.xml" system="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:gov.nist.mscp.content.cpe.oval:def:1</check><cpe-23:cpe23-item name="cpe:2.3:{2}:*:*:*:*:*:*:*"/></cpe-item></cpe-list></component><component id="scap_gov.nist.mscp.content_comp_macOS_{0}_macOS-cpe-oval.xml" timestamp="{1}"><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5 https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#macos https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/macos-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/unix-definitions-schema.xsd"><generator><oval:product_name>macOS Security Compliance Project</oval:product_name><oval:schema_version>5.12.1</oval:schema_version><oval:timestamp>{1}</oval:timestamp></generator><definitions><definition id="oval:gov.nist.mscp.content.cpe.oval:def:1" version="1" class="inventory">  <metadata>    <title>Apple macOS {0} is installed</title>    <affected family="macos">      <platform>macOS</platform>    </affected>    <reference source="CPE" ref_id="cpe:/{2}"/>    <description>The operating system installed on the system is Apple macOS ({0}).</description>  </metadata>  <criteria operator="AND">    <criterion comment="The Installed Operating System is Part of the Mac OS Family" test_ref="oval:gov.nist.mscp.content.cpe:tst:1"/>    <criterion comment="Apple macOS version is greater than or equal to {0}" test_ref="oval:gov.nist.mscp.content.cpe:tst:2"/>  </criteria></definition></definitions><tests><family_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" check="all" check_existence="only_one_exists" comment="The Installed Operating System is Part of the macOS Family" id="oval:gov.nist.mscp.content.cpe:tst:1" version="1">  <object object_ref="oval:gov.nist.mscp.content.cpe:obj:1"/>  <state state_ref="oval:gov.nist.mscp.content.cpe:ste:1"/></family_test><plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="Apple macOS version is greater than {0}" id="oval:gov.nist.mscp.content.cpe:tst:2" version="2">  <object object_ref="oval:gov.nist.mscp.content.cpe:obj:2"/>  <state state_ref="oval:gov.nist.mscp.content.cpe:ste:2"/></plist511_test></tests><objects><family_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:gov.nist.mscp.content.cpe:obj:1" version="1" comment="This variable_object represents the family that the operating system belongs to."/><plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="The macOS product version plist object." id="oval:gov.nist.mscp.content.cpe:obj:2" version="1">  <filepath>/System/Library/CoreServices/SystemVersion.plist</filepath>  <xpath>//*[contains(text(), "ProductVersion")]/following-sibling::*[1]/text()</xpath></plist511_object></objects><states><family_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:gov.nist.mscp.content.cpe:ste:1" version="1" comment="The OS is part of the macOS Family.">  <family>macos</family></family_state><plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="Is the value is greater than or equal to {0}" id="oval:gov.nist.mscp.content.cpe:ste:2" version="1"><value_of datatype="version" operation="greater than or equal">{0}</value_of></plist511_state></states></oval_definitions></component>""".format(
            current_version_data["os_version"],
            date_time_string,
            current_version_data["cpe"],
        )

        scap = scap + xccdf + oval + ocil + cpe + "</data-stream-collection>"

    totaloutput = str()
    filenameversion = (
        str(current_version_data["revision"])
        .split(", ", maxsplit=1)[-1]
        .replace(" ", "_")
    )

    base_filename: str = f"{args.os_name}_{current_version_data.get('os_version', None)}_Security_Compliance_Benchmark-Revision-{filenameversion}.xml"

    if args.oval:
        base_filename = base_filename.replace(".xml", "_oval.xml")
        totaloutput = pretty_format_xml(
            oval
            + oval_prefix
            + oval_def
            + oval_tests
            + oval_objects
            + oval_states
            + "</oval_definitions>"
        )

    if args.xccdf:
        base_filename = base_filename.replace(".xml", "_xccdf.xml")
        totaloutput = pretty_format_xml(
            xccdf
            + xccdfPrefix
            + xccdfProfiles
            + xccdf_group
            + xccdfrules
            + xccdf_closer
        )

    if args.os_name != "macos" and args.oval:
        logger.error("OVAL generation is only available for MacOS")
        sys.exit()

    if args.os_name != "macos" and args.oval is None and args.xccdf is None:
        logger.error("SCAP generation is only available for MacOS")
        sys.exit()

    if args.oval is None and args.xccdf is None and args.os_name == "macos":
        scap = """<?xml version="1.0" encoding="UTF-8"?><data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2" id="scap_gov.nist.mscp.content_collection_macOS_{0}.0" schematron-version="1.4"><data-stream timestamp="{1}" id="scap_gov.nist.mscp.content_datastream_macOS_{0}.0" scap-version="1.4" use-case="CONFIGURATION"><dictionaries><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_macOS-cpe-dictionary.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_macOS-cpe-dictionary.xml"><catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">  <uri name="macOS-cpe-oval.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{0}_macOS-cpe-oval.xml"/></catalog></component-ref></dictionaries><checklists><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_xccdf.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_xccdf.xml"><catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">  <uri name="oval.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{0}_check_1"/>  <uri name="ocil.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{0}_check_2"/></catalog></component-ref></checklists><checks><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_macOS-cpe-oval.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_macOS-cpe-oval.xml"/><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_check_1" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_check_1"/><component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{0}_check_2" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{0}_check_2"/></checks></data-stream>""".format(
            current_version_data["os_version"], date_time_string
        )

        xccdf = (
            '<component id="scap_gov.nist.mscp.content_comp_macOS_{0}_xccdf.xml" timestamp="{1}">'.format(
                current_version_data["os_version"], date_time_string
            )
            + xccdfPrefix
            + xccdfProfiles
            + xccdf_group
            + xccdfrules
            + xccdf_closer
            + "</component>"
        )

        oval = (
            '<component id="scap_gov.nist.mscp.content_comp_macOS_{0}_check_1" timestamp="{1}">'.format(
                current_version_data["os_version"], date_time_string
            )
            + oval_prefix
            + oval_def
            + oval_tests
            + oval_objects
            + oval_states
            + "</oval_definitions></component>"
        )

        ocil = """<component id="scap_gov.nist.mscp.content_comp_macOS_{0}_check_2" timestamp="2025-11-05T10:30:43"><ocil xmlns="http://scap.nist.gov/schema/ocil/2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://scap.nist.gov/schema/ocil/2.0 ocil-2.0.xsd"><generator><product_name>Manual Labor</product_name><product_version>1</product_version><schema_version>2.0</schema_version><timestamp>{0}</timestamp></generator><questionnaires><questionnaire id="ocil:gov.nist.mscp.content:questionnaire:1">  <title>Obtain a pass or a fail</title>  <actions>    <test_action_ref>ocil:gov.nist.mscp.content:testaction:1</test_action_ref>  </actions></questionnaire></questionnaires><test_actions><boolean_question_test_action id="ocil:gov.nist.mscp.content:testaction:1" question_ref="ocil:gov.nist.mscp.content:question:1">  <when_true>    <result>PASS</result>  </when_true>  <when_false>    <result>FAIL</result>  </when_false></boolean_question_test_action></test_actions><questions><boolean_question id="ocil:gov.nist.mscp.content:question:1">  <question_text>Do you wish this checklist item to be considered to have passed?</question_text></boolean_question></questions></ocil></component>""".format(
            date_time_string
        )

        cpe = """<component id="scap_gov.nist.mscp.content_comp_macOS_{0}_macOS-cpe-dictionary.xml" timestamp="{1}"><?xml-model href="https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd" schematypens="http://www.w3.org/2001/XMLSchema" title="CPE XML schema"?><cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0" xmlns:cpe-23="http://scap.nist.gov/schema/cpe-extension/2.3"><generator><product_name>macOS Security Compliance Project</product_name><schema_version>2.3</schema_version><timestamp>{1}</timestamp></generator><cpe-item name="cpe:/{2}"><title xml:lang="en-US">Apple macOS {0}</title><notes xml:lang="en-US">  <note>This CPE Name represents macOS {0}</note></notes><check href="macOS-cpe-oval.xml" system="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:gov.nist.mscp.content.cpe.oval:def:1</check><cpe-23:cpe23-item name="cpe:2.3:{2}:*:*:*:*:*:*:*"/></cpe-item></cpe-list></component><component id="scap_gov.nist.mscp.content_comp_macOS_{0}_macOS-cpe-oval.xml" timestamp="{1}"><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5 https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#macos https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/macos-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/unix-definitions-schema.xsd"><generator><oval:product_name>macOS Security Compliance Project</oval:product_name><oval:schema_version>5.12.1</oval:schema_version><oval:timestamp>{1}</oval:timestamp></generator><definitions><definition id="oval:gov.nist.mscp.content.cpe.oval:def:1" version="1" class="inventory">  <metadata>    <title>Apple macOS {0} is installed</title>    <affected family="macos">      <platform>macOS</platform>    </affected>    <reference source="CPE" ref_id="cpe:/{2}"/>    <description>The operating system installed on the system is Apple macOS ({0}).</description>  </metadata>  <criteria operator="AND">    <criterion comment="The Installed Operating System is Part of the Mac OS Family" test_ref="oval:gov.nist.mscp.content.cpe:tst:1"/>    <criterion comment="Apple macOS version is greater than or equal to {0}" test_ref="oval:gov.nist.mscp.content.cpe:tst:2"/>  </criteria></definition></definitions><tests><family_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" check="all" check_existence="only_one_exists" comment="The Installed Operating System is Part of the macOS Family" id="oval:gov.nist.mscp.content.cpe:tst:1" version="1">  <object object_ref="oval:gov.nist.mscp.content.cpe:obj:1"/>  <state state_ref="oval:gov.nist.mscp.content.cpe:ste:1"/></family_test><plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="Apple macOS version is greater than {0}" id="oval:gov.nist.mscp.content.cpe:tst:2" version="2">  <object object_ref="oval:gov.nist.mscp.content.cpe:obj:2"/>  <state state_ref="oval:gov.nist.mscp.content.cpe:ste:2"/></plist511_test></tests><objects><family_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:gov.nist.mscp.content.cpe:obj:1" version="1" comment="This variable_object represents the family that the operating system belongs to."/><plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="The macOS product version plist object." id="oval:gov.nist.mscp.content.cpe:obj:2" version="1">  <filepath>/System/Library/CoreServices/SystemVersion.plist</filepath>  <xpath>//*[contains(text(), "ProductVersion")]/following-sibling::*[1]/text()</xpath></plist511_object></objects><states><family_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:gov.nist.mscp.content.cpe:ste:1" version="1" comment="The OS is part of the macOS Family.">  <family>macos</family></family_state><plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="Is the value is greater than or equal to {0}" id="oval:gov.nist.mscp.content.cpe:ste:2" version="1"><value_of datatype="version" operation="greater than or equal">{0}</value_of></plist511_state></states></oval_definitions></component>""".format(
            current_version_data["os_version"],
            date_time_string,
            current_version_data["cpe"],
        )

        totaloutput = pretty_format_xml(
            scap + xccdf + oval + ocil + cpe + "</data-stream-collection>"
        )

    output_file = output_file / base_filename

    with open(output_file, "w") as rite:
        rite.write(totaloutput)
        rite.close()
