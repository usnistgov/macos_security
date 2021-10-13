#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given keyword, and output a baseline file

import os.path
import glob
import os
import yaml
import argparse


class MacSecurityRule():
    def __init__(self, title, rule_id, severity, discussion, check, fix, cci, cce, nist_controls, disa_stig, srg, tags, result_value, mobileconfig, mobileconfig_info):
        self.rule_title = title
        self.rule_id = rule_id
        self.rule_severity = severity
        self.rule_discussion = discussion
        self.rule_check = check
        self.rule_fix = fix
        self.rule_cci = cci
        self.rule_cce = cce
        self.rule_80053r4 = nist_controls
        self.rule_disa_stig = disa_stig
        self.rule_srg = srg
        self.rule_result_value = result_value
        self.rule_tags = tags
        self.rule_mobileconfig = mobileconfig
        self.rule_mobileconfig_info = mobileconfig_info

    def create_asciidoc(self, adoc_rule_template):
        """Pass an AsciiDoc template as file object to return formatted AsciiDOC"""
        rule_adoc = ""
        rule_adoc = adoc_rule_template.substitute(
            rule_title=self.rule_title,
            rule_id=self.rule_id,
            rule_severity=self.rule_severity,
            rule_discussion=self.rule_discussion,
            rule_check=self.rule_check,
            rule_fix=self.rule_fix,
            rule_cci=self.rule_cci,
            rule_80053r4=self.rule_80053r4,
            rule_disa_stig=self.rule_disa_stig,
            rule_srg=self.rule_srg,
            rule_result=self.rule_result_value
        )
        return rule_adoc


def get_rule_yaml(rule_file, custom=False):
    """ Takes a rule file, checks for a custom version, and returns the yaml for the rule
    """
    resulting_yaml = {}
    names = [os.path.basename(x) for x in glob.glob('../custom/rules/**/*.yaml', recursive=True)]
    file_name = os.path.basename(rule_file)
    # if file_name in names:
    #     print(f"Custom settings found for rule: {rule_file}")
    #     try:
    #         override_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
    #     except IndexError:
    #         override_path = glob.glob('../custom/rules/{}'.format(file_name), recursive=True)[0]
    #     with open(override_path) as r:
    #         rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    #     r.close()
    # else:
    #     with open(rule_file) as r:
    #         rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    #     r.close()
    if custom:
        print(f"Custom settings found for rule: {rule_file}")
        try:
            override_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
        except IndexError:
            override_path = glob.glob('../custom/rules/{}'.format(file_name), recursive=True)[0]
        with open(override_path) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    else:
        with open(rule_file) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    
    try:
        og_rule_path = glob.glob('../rules/**/{}'.format(file_name), recursive=True)[0]
    except IndexError:
        #assume this is a completely new rule
        og_rule_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
    
    # get original/default rule yaml for comparison
    with open(og_rule_path) as og:
        og_rule_yaml = yaml.load(og, Loader=yaml.SafeLoader)
    og.close()

    for yaml_field in og_rule_yaml:
        try:
            if og_rule_yaml[yaml_field] == rule_yaml[yaml_field]:
                resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
            else:
                resulting_yaml[yaml_field] = rule_yaml[yaml_field]
                if 'customized' in resulting_yaml:
                    resulting_yaml['customized'].append("customized {}".format(yaml_field))
                else:
                    resulting_yaml['customized'] = ["customized {}".format(yaml_field)]
        except KeyError:
            resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]

    return resulting_yaml

def collect_rules():
    """Takes a baseline yaml file and parses the rules, returns a list of containing rules
    """
    all_rules = []
    #expected keys and references
    keys = ['mobileconfig',
            'macOS',
            'severity',
            'title',
            'check',
            'fix',
            'tags',
            'id',
            'references',
            'result',
            'discussion']
    references = ['disa_stig',
                  'cci',
                  'cce',
                  '800-53r4',
                  'srg']


    for rule in glob.glob('../rules/**/*.yaml',recursive=True) + glob.glob('../custom/rules/**/*.yaml',recursive=True):
        rule_yaml = get_rule_yaml(rule, custom=False)
        for key in keys:
            try:
                rule_yaml[key]
            except:
                #print "{} key missing ..for {}".format(key, rule)
                rule_yaml.update({key: "missing"})
            if key == "references":
                for reference in references:
                    try:
                        rule_yaml[key][reference]
                    except:
                        #print("expected reference '{}' is missing in key '{}' for rule{}".format(reference, key, rule))
                        rule_yaml[key].update({reference: ["None"]})
        
        all_rules.append(MacSecurityRule(rule_yaml['title'].replace('|', '\|'),
                                    rule_yaml['id'].replace('|', '\|'),
                                    rule_yaml['severity'].replace('|', '\|'),
                                    rule_yaml['discussion'].replace('|', '\|'),
                                    rule_yaml['check'].replace('|', '\|'),
                                    rule_yaml['fix'].replace('|', '\|'),
                                    rule_yaml['references']['cci'],
                                    rule_yaml['references']['cce'],
                                    rule_yaml['references']['800-53r4'],
                                    rule_yaml['references']['disa_stig'],
                                    rule_yaml['references']['srg'],
                                    rule_yaml['tags'],
                                    rule_yaml['result'],
                                    rule_yaml['mobileconfig'],
                                    rule_yaml['mobileconfig_info']
                                    ))

    return all_rules

def create_args():
    """configure the arguments used in the script, returns the parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Given a keyword tag, generate a generic baseline.yaml file containing rules with the tag.')
    parser.add_argument("-c", "--controls", default=None,
                        help="Output the 800-53 controls covered by the rules.", action="store_true")
    parser.add_argument("-k", "--keyword", default=None,
                        help="Keyword tag to collect rules containing the tag.", action="store")
    parser.add_argument("-l", "--list_tags", default=None,
                        help="List the available keyword tags to search for.", action="store_true")
    
    return parser.parse_args()

def section_title(section_name):
    titles = {
        "auth": "authentication",
        "audit": "auditing",
        "os": "macos",
        "pwpolicy": "passwordpolicy",
        "icloud": "icloud",
        "sysprefs": "systempreferences",
        "srg": "srg"
    }
    if section_name in titles:
        return titles[section_name]
    else:
        return section_name

def get_controls(all_rules):
    all_controls = []
    for rule in all_rules:
        for control in rule.rule_80053r4:
            if control not in all_controls:
                all_controls.append(control)
    
    all_controls.sort()
    
    return all_controls

    

def available_tags(all_rules):
    all_tags = []
    for rule in all_rules:
        for tag in rule.rule_tags:
            all_tags.append(tag)

    available_tags = []
    for tag in all_tags:
        if tag not in available_tags:
            available_tags.append(tag)
    available_tags.append("all_rules")
    available_tags.sort()

    for tag in available_tags:
        print(tag)
    return

def output_baseline(rules, os, keyword):
    inherent_rules = []
    permanent_rules = []
    na_rules = []
    supplemental_rules = []
    other_rules = []
    sections = []
    output_text = ""

    for rule in rules:
        if "inherent" in rule.rule_tags:
            inherent_rules.append(rule.rule_id)
        elif "permanent" in rule.rule_tags:
            permanent_rules.append(rule.rule_id)
        elif "n_a" in rule.rule_tags:
            na_rules.append(rule.rule_id)
        elif "supplemental" in rule.rule_tags:
            supplemental_rules.append(rule.rule_id)
        else:
            if rule.rule_id not in other_rules:
                other_rules.append(rule.rule_id)
            section_name = rule.rule_id.split("_")[0]
            if section_name not in sections:
                sections.append(section_name)

    output_text = f'title: "macOS {os}: Security Configuration - {keyword}"\n'
    output_text += f'description: |\n  This guide describes the actions to take when securing a macOS {os} system against the {keyword} baseline.\n'
    output_text += f'authors: |\n  |===\n  |Name|Organization\n  |===\n'
    output_text += 'profile:\n'
    
    # sort the rules
    other_rules.sort()
    inherent_rules.sort()
    permanent_rules.sort()
    na_rules.sort()
    supplemental_rules.sort()

    if len(other_rules) > 0:
        for section in sections:
            output_text += ('  - section: "{}"\n'.format(section_title(section)))
            output_text += ("    rules:\n")
            for rule in other_rules:
                if rule.startswith(section):
                    output_text += ("      - {}\n".format(rule))
    
    if len(inherent_rules) > 0:
        output_text += ('  - section: "Inherent"\n')
        output_text += ("    rules:\n")
        for rule in inherent_rules:
            output_text += ("      - {}\n".format(rule))

    if len(permanent_rules) > 0:
        output_text += ('  - section: "Permanent"\n')
        output_text += ("    rules:\n")
        for rule in permanent_rules:
            output_text += ("      - {}\n".format(rule))

    if len(na_rules) > 0:
        output_text += ('  - section: "not_applicable"\n')
        output_text += ("    rules: \n")
        for rule in na_rules:
            output_text += ("      - {}\n".format(rule))

    if len(supplemental_rules) > 0:
        output_text += ('  - section: "Supplemental"\n')
        output_text += ("    rules:\n")
        for rule in supplemental_rules:
            output_text += ("      - {}\n".format(rule))
    
    return output_text


def main():

    args = create_args()
    try:
        # output_basename = os.path.basename(args.baseline.name)
        # output_filename = os.path.splitext(output_basename)[0]
        # baseline_name = os.path.splitext(output_basename)[0].capitalize()
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)

        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)
    
        all_rules = collect_rules()

        if args.list_tags:
            available_tags(all_rules)
            return

        if args.controls:
            baselines_file = os.path.join(
            parent_dir, 'includes', '800-53_baselines.yaml')


            with open(baselines_file) as r:
                baselines = yaml.load(r, Loader=yaml.SafeLoader)
            
            included_controls = get_controls(all_rules)
            needed_controls = []
        
            for control in baselines['low']:
                if control not in needed_controls:
                    needed_controls.append(control)
            
            for n_control in needed_controls:
                if n_control not in included_controls:
                    print(f'{n_control} missing from any rule, needs a rule, or included in supplemental')

            return

        build_path = os.path.join(parent_dir, 'build', 'baselines')
        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")

    except IOError as msg:
        parser.error(str(msg))

    version_file = os.path.join(parent_dir, "VERSION.yaml")
    with open(version_file) as r:
        version_yaml = yaml.load(r, Loader=yaml.SafeLoader)   

    found_rules = []
    for rule in all_rules:
        if args.keyword in rule.rule_tags or args.keyword == "all_rules":
            found_rules.append(rule)
        # assume all baselines will contain the supplemental rules
        if "supplemental" in rule.rule_tags:
            if rule not in found_rules:
                found_rules.append(rule)
    
    if args.keyword == None:
        print("No rules found for the keyword provided, please verify from the following list:")
        available_tags(all_rules)
    else:
        baseline_output_file = open(f"{build_path}/{args.keyword}.yaml", 'w')
        baseline_output_file.write(output_baseline(found_rules, version_yaml["os"], args.keyword))
    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()
