#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given keyword, and output a baseline file

from operator import truediv
import os.path
import glob
import os
import yaml
from yaml.representer import SafeRepresenter
import argparse

class LiteralString(str):
    pass


def change_style(style, representer):
    def new_representer(dumper, data):
        scalar = representer(dumper, data)
        scalar.style = style
        return scalar
    return new_representer

def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')

represent_literal_str = change_style('|', SafeRepresenter.represent_str)


yaml.add_representer(LiteralString, represent_literal_str)
yaml.add_representer(type(None), represent_none)

class MacSecurityRule():
    def __init__(self, title, rule_id, severity, discussion, check, fix, cci, cce, nist_controls, disa_stig, srg, macos, odv, tags, result_value, mobileconfig, mobileconfig_info):
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
        self.rule_macOS = macos
        self.rule_odv = odv
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
    
    with open(rule_file) as r:
        rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)

    return rule_yaml

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
            'odv',
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


    for rule in glob.glob('../rules/**/*.yaml',recursive=True):
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
                                    rule_yaml['macOS'],
                                    rule_yaml['odv'],
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
    parser.add_argument("macOS", default=None,
                        help="Version of macOS you are building a baseline for.", action="store")
    
    return parser.parse_args()

def getCCE(rule):
    try:
        return rule["references"]["cce"]
    except KeyError:
        print(f"no CCE for {rule['id']}")
        return ["N/A"]
def getSTIG(rule):
    try:
        return rule["references"]["disa_stig"]
    except KeyError:
        print(f"no disa_stig for {rule['id']}")
        return ["N/A"]

def getDiscussion(rule):
    try:
        return rule["discussion"]
    except KeyError:
        print(f"no discussion for {rule['id']}")
        return "N/A"
def getCheck(rule):
    try:
        return rule["check"]
    except KeyError:
        print(f"no check for {rule['id']}")
        return "N/A"
def getFix(rule):
    try:
        return rule["fix"]
    except KeyError:
        print(f"no fix for {rule['id']}")
        return "N/A"

def write_odv_custom_rule(rule, odv):
    print(f"Writing custom rule for {rule.rule_id} to include value {odv}")
    odv_yaml = f'odv: {odv}'
    odv_output_file = open(f"../custom/rules/{rule.rule_id}.yaml", 'w')
    odv_output_file.write(odv_yaml)    
    return


def main():

    args = create_args()
    try:
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)

        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)
    
        all_rules = collect_rules()

       
        build_path = os.path.join(parent_dir, 'build', args.macOS)
        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")

    except IOError as msg:
        parser.error(str(msg))


    # found_rules = []
    # for rule in all_rules:
    #     print(rule)
    mont_rule_list = []
    for rule in glob.glob('../rules/**/*.yaml',recursive=True):
        rule_yaml = get_rule_yaml(rule, custom=False)
        mont_rule_list.append(rule_yaml) 
    
    for rule in mont_rule_list:
        cce = getCCE(rule)
        stig = getSTIG(rule)
        check = getCheck(rule)
        discussion = getDiscussion(rule)
        fix = getFix(rule)
        
        rule['discussion'] = LiteralString(discussion)
        rule['check'] = LiteralString(check)
        rule['fix'] = LiteralString(fix)
        rule['references']['cce'] = LiteralString("$VALUE")
        rule['references']['disa_stig'] = LiteralString("$VALUE")
        rule['macOS']={args.macOS : {'references': {'cce' : cce, 'disa_stig' : stig } } }
        output_path = os.path.join(build_path, rule['id'] + '.yaml')
        with open(output_path, 'w') as yaml_file:
            yaml.dump(rule, yaml_file, indent=2, sort_keys=False)
    
    
    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()

