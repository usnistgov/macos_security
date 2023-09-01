#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given keyword, and output a baseline file

import os.path
import glob
import os
import yaml
import csv

class MacSecurityRule():
    def __init__(self, title, rule_id, severity, discussion, check, fix, cci, cce, nist_controls, disa_stig, srg, odv, tags, result_value, mobileconfig, mobileconfig_info):
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
        self.rule_odv = odv
        self.rule_result_value = result_value
        self.rule_tags = tags
        self.rule_mobileconfig = mobileconfig
        self.rule_mobileconfig_info = mobileconfig_info

def get_rule_yaml(rule_file, custom=False):
    """ Takes a rule file, checks for a custom version, and returns the yaml for the rule
    """
    resulting_yaml = {}
    names = [os.path.basename(x) for x in glob.glob('../custom/rules/**/*.yaml', recursive=True)]
    file_name = os.path.basename(rule_file)

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
            'mobileconfig_info'
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


    for rule in sorted(glob.glob('../rules/**/*.yaml',recursive=True)) + sorted(glob.glob('../custom/rules/**/*.yaml',recursive=True)):
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
                                    rule_yaml['odv'],
                                    rule_yaml['tags'],
                                    rule_yaml['result'],
                                    rule_yaml['mobileconfig'],
                                    rule_yaml['mobileconfig_info']
                                    ))

    return all_rules


def get_rule_from_stig_id(stigid, srgid, rules):
    found = False
    for _r in rules:
        if stigid in _r.rule_disa_stig:
            print(f'{stigid} is mapped to {_r.rule_id}')
            for _srg in srgid:
                rule_srgs = [x.strip(' ') for x in _r.rule_srg]
                if _srg.strip(' ') in rule_srgs:
                    continue
                else:
                    print(f'{_srg} is not found in mapped rule: {_r.rule_id}')
            found = True
    
    if not found:
        print(f'{stigid} is not mapped to any MSCP rule')

def build_dict(seq, key):
    return dict((d[key], dict(d, index=index)) for (index, d) in enumerate(seq))


def main():

    try:
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)

        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)
    
        all_rules = collect_rules()

        build_path = os.path.join(parent_dir, 'build', 'baselines')
        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")

    except IOError as msg:
        parser.error(str(msg))

    # import mscp-data
    mscp_data_file = os.path.join(
            parent_dir, 'includes', 'mscp-data.yaml')
    with open(mscp_data_file) as r:
        mscp_data_yaml = yaml.load(r, Loader=yaml.SafeLoader)

    # import stig data
    stig_data_file = os.path.join(
            parent_dir, 'build', 'stig_mapping_ventura.yaml')
    with open(stig_data_file) as r:
        stig_data_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    
    # import SRG data
    srg_data_file = os.path.join(
            parent_dir, 'includes', 'U_GPOS_SRG_V2R6_STIGTemplate.yaml')
    with open(srg_data_file) as r:
        srg_data_yaml = yaml.load(r, Loader=yaml.SafeLoader)

    version_file = os.path.join(parent_dir, "VERSION.yaml")
    with open(version_file) as r:
        version_yaml = yaml.load(r, Loader=yaml.SafeLoader)   

    found_rules = []
    for rule in all_rules:
        if "newstig" in rule.rule_tags:
            found_rules.append(rule)


    fields= ["IA Control", "CCI", "SRGID", "STIGID", 'SRG Requirement', "Requirement", 'SRG VulDiscussion', "VulDiscussion", "Status", 'SRG Check', "Check", 'SRG Fix', "Fix", "Severity", "Mitigation", "Artifact Description", "Status Justification",'index']
    requirements = []
    srgs_by_ID = build_dict(srg_data_yaml, key="SRGID")


    srgids = []
    for _requirement in srg_data_yaml:
        srgids.append(_requirement['SRGID'])
    
    for _srgid in srgids:
        if not any(_srgid in rule.rule_srg for rule in found_rules):
            print(f'{_srgid} is not mapped to MSCP rule')
            _r = srgs_by_ID.get(_srgid)
            _r["Status"] = "Does Not Meet"
            requirements.append(_r)


        else:
            for rule in all_rules:
                print(f'processing {rule.rule_id}...')
                if _srgid in rule.rule_srg:
                    print(f'looking for {_srgid} in {rule.rule_id}...')
                    _req = srgs_by_ID.get(_srgid)
                    _new_req = _req.copy()
                    if "inherent" in rule.rule_tags:
                        _new_req["Status"] = "Inherently Met"
                    elif "permanent" in rule.rule_tags:
                        _new_req["Status"] = "Permanent - does not meet"
                    elif "n_a" in rule.rule_tags:
                        _new_req["Status"] = "Not Applicible"
                    else:
                        _new_req["Status"] = "Applicible - Configurable"
                    
                    _new_req["Requirement"] = rule.rule_title
                    _new_req["Artifact Description"] = rule.rule_id
                    _new_req["VulDiscussion"] = rule.rule_discussion
                    _new_req["Check"] = rule.rule_check
                    _new_req["Fix"] = rule.rule_fix
                    
                    if _new_req not in requirements:
                        requirements.append(_new_req)

    with open('../build/srg_mscp.csv', 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(requirements)
    
    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()