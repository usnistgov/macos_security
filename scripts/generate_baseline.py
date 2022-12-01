#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given keyword, and output a baseline file

import os.path
import glob
import os
import yaml
import argparse


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
    parser.add_argument("-t", "--tailor", default=None,
                        help="Customize the baseline to your organizations values.", action="store_true")
    
    return parser.parse_args()

def section_title(section_name):
    titles = {
        "auth": "authentication",
        "audit": "auditing",
        "os": "macos",
        "pwpolicy": "passwordpolicy",
        "icloud": "icloud",
        "sysprefs": "systempreferences",
        "system_settings": "systemsettings",
        "sys_prefs": "systempreferences",
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

def append_authors(authors, name, org):
    author_block = "*Security configuration tailored by:*\n  "
    author_block += "|===\n  "
    author_block += f"|{name}|{org}\n  "
    author_block += "|===\n  "
    author_block += authors
    return author_block

def parse_authors(authors_from_yaml):
    author_block = "*macOS Security Compliance Project*\n\n  "
    #  |\n  |===\n  |Name|Organization\n  |===\n
    if "preamble" in authors_from_yaml.keys():
        preamble = authors_from_yaml['preamble']
        author_block += f'{preamble}\n  '
        
    author_block += "|===\n  "
    for name in authors_from_yaml['names']:
        author_block += f'|{name}\n  '
    author_block += "|===\n"
    return author_block

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

def output_baseline(rules, os, baseline_tailored_string, benchmark, authors, full_title):
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
            if rule.rule_id.startswith("system_settings"):
                 section_name = rule.rule_id.split("_")[0]+"_"+rule.rule_id.split("_")[1]
            else:
                 section_name = rule.rule_id.split("_")[0]
            if section_name not in sections:
                sections.append(section_name)
    if baseline_tailored_string:
        output_text = f'title: "macOS {os}: Security Configuration -{full_title} {baseline_tailored_string}"\n'
        output_text += f'description: |\n  This guide describes the actions to take when securing a macOS {os} system against the{full_title} {baseline_tailored_string} security baseline.\n'
    else:
        output_text = f'title: "macOS {os}: Security Configuration -{full_title}"\n'
        output_text += f'description: |\n  This guide describes the actions to take when securing a macOS {os} system against the{full_title} security baseline.\n'
    
    if benchmark == "recommended":
        output_text += "\n  Information System Security Officers and benchmark creators can use this catalog of settings in order to assist them in security benchmark creation. This list is a catalog, not a checklist or benchmark, and satisfaction of every item is not likely to be possible or sensible in many operational scenarios.\n"
  
    # # process authors
    output_text += f'authors: |\n  {authors}'

    output_text += f'parent_values: "{benchmark}"\n'
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

def write_odv_custom_rule(rule, odv):
    print(f"Writing custom rule for {rule.rule_id} to include value {odv}")
    
    if not os.path.exists("../custom/rules"):
        os.makedirs("../custom/rules")
    if os.path.exists(f"../custom/rules/{rule.rule_id}.yaml"):
        with open(f"../custom/rules/{rule.rule_id}.yaml") as f:
            rule_yaml = yaml.load(f, Loader=yaml.SafeLoader)
    else:
        rule_yaml = {}

    # add odv to rule_yaml    
    rule_yaml['odv'] = {"custom" : odv}
    with open(f"../custom/rules/{rule.rule_id}.yaml", 'w') as f:
      yaml.dump(rule_yaml, f, explicit_start=True)    
    
    return

def remove_odv_custom_rule(rule):
    odv_yaml = {}
    try:
        with open(f"../custom/rules/{rule.rule_id}.yaml") as f:
            odv_yaml = yaml.load(f, Loader=yaml.SafeLoader)
            odv_yaml.pop('odv', None)
    except:
        pass

    if odv_yaml:
        with open(f"../custom/rules/{rule.rule_id}.yaml", 'w') as f:
            yaml.dump(odv_yaml, f, explicit_start=True)
    else:
        if os.path.exists(f"../custom/rules/{rule.rule_id}.yaml"):
            os.remove(f"../custom/rules/{rule.rule_id}.yaml")
    
def sanitised_input(prompt, type_=None, range_=None, default_=None):
    while True:
        ui = input(prompt) or default_
        if type_ is not None:
            try:
                ui = type_(ui)
            except ValueError:
                print("Input type must be {0}.".format(type_.__name__))
                continue
        if type_ is str:
            if ui.isnumeric():
                print("Input type must be {0}.".format(type_.__name__))
                continue

        if range_ is not None and ui not in range_:
            if isinstance(range_, range):
                template = "Input must be between {0.start} and {0.stop}."
                print(template.format(range_))
            else:
                template = "Input must be {0}."
                if len(range_) == 1:
                    print(template.format(*range_))
                else:
                    expected = " or ".join((
                        ", ".join(str(x) for x in range_[:-1]),
                        str(range_[-1])
                    ))
                    print(template.format(expected))
        else:
            return ui

def odv_query(rules, benchmark):
    print("The inclusion of any given rule is a risk-based-decision (RBD).  While each rule is mapped to an 800-53 control, deploying it in your organization should be part of the decision-making process. \nYou will be prompted to include each rule, and for those with specific organizational defined values (ODV), you will be prompted for those as well.\n")
    
    if not benchmark == "recommended":
        print(f"WARNING: You are attempting to tailor an already established benchmark.  Excluding rules or modifying ODVs may not meet the compliance of the established benchmark.\n")
        
    included_rules = []
    queried_rule_ids = []
    
    include_all = False

    for rule in rules:
        get_odv = False
       
        _always_include = ['inherent']
        if any(tag in rule.rule_tags for tag in _always_include):
            #print(f"Including rule {rule.rule_id} by default")
            include = "Y"
        elif include_all:
            if rule.rule_id not in queried_rule_ids:
                include = "Y"
                get_odv = True
                queried_rule_ids.append(rule.rule_id)
                remove_odv_custom_rule(rule)
        else:
            if rule.rule_id not in queried_rule_ids:
                include = sanitised_input(f"Would you like to include the rule for \"{rule.rule_id}\" in your benchmark? [Y/n/all/?]: ", str.lower, range_=('y', 'n', 'all', '?'), default_="y")
                if include == "?":
                    print(f'Rule Details: \n{rule.rule_discussion}')
                    include = sanitised_input(f"Would you like to include the rule for \"{rule.rule_id}\" in your benchmark? [Y/n/all]: ", str.lower, range_=('y', 'n', 'all'), default_="y")
                queried_rule_ids.append(rule.rule_id)
                get_odv = True
                # remove custom ODVs if there, they will be re-written if needed
                remove_odv_custom_rule(rule)
                if include.upper() == "ALL":
                    include_all = True
                    include = "y"
        if include.upper() == "Y":
            included_rules.append(rule)
            if rule.rule_odv == "missing":
                continue
            elif get_odv:
                if benchmark == "recommended":
                    print(f'{rule.rule_odv["hint"]}')
                    if isinstance(rule.rule_odv["recommended"], int):
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the recommended value ({rule.rule_odv["recommended"]}): ', int, default_=rule.rule_odv["recommended"])
                    elif isinstance(rule.rule_odv["recommended"], bool):
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the recommended value ({rule.rule_odv["recommended"]}): ', bool, default_=rule.rule_odv["recommended"])
                    else:
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the recommended value ({rule.rule_odv["recommended"]}): ', str, default_=rule.rule_odv["recommended"])
                    if odv and odv != rule.rule_odv["recommended"]:
                        write_odv_custom_rule(rule, odv)
                else:
                    print(f'\nODV value: {rule.rule_odv["hint"]}')
                    if isinstance(rule.rule_odv[benchmark], int):
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the default value ({rule.rule_odv[benchmark]}): ', int, default_=rule.rule_odv[benchmark])
                    elif isinstance(rule.rule_odv[benchmark], bool):
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the default value ({rule.rule_odv[benchmark]}): ', bool, default_=rule.rule_odv[benchmark])
                    else:
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the default value ({rule.rule_odv[benchmark]}): ', str, default_=rule.rule_odv[benchmark])
                    if odv and odv != rule.rule_odv[benchmark]:
                        write_odv_custom_rule(rule, odv)
    return included_rules

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

    # import mscp-data
    mscp_data_file = os.path.join(
            parent_dir, 'includes', 'mscp-data.yaml')
    with open(mscp_data_file) as r:
        mscp_data_yaml = yaml.load(r, Loader=yaml.SafeLoader)

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
        _established_benchmarks = ['stig', 'cis_lvl1', 'cis_lvl2']
        if any(bm in args.keyword for bm in _established_benchmarks):
            benchmark = args.keyword
        else:
            benchmark = "recommended"
        
        if mscp_data_yaml['authors'][args.keyword]:
            authors = parse_authors(mscp_data_yaml['authors'][args.keyword])
        else:
            authors = "|\n  |===\n  |Name|Organization\n  |===\n"
        
        if mscp_data_yaml['titles'][args.keyword] and not args.tailor:
            full_title = f" {mscp_data_yaml['titles'][args.keyword]}"
        elif args.tailor:
            full_title = ""
        else:
            full_title = f" {args.keyword}"
        
        baseline_tailored_string = ""
        if args.tailor:
            # prompt for name of benchmark to be used for filename
            tailored_filename = sanitised_input(f'Enter a name for your tailored benchmark or press Enter for the default value ({args.keyword}): ', str, default_=args.keyword)
            custom_author_name = sanitised_input('Enter your name: ')
            custom_author_org = sanitised_input('Enter your organization: ')
            authors = append_authors(authors, custom_author_name, custom_author_org)
            if tailored_filename == args.keyword:
                baseline_tailored_string = f"{args.keyword.upper()} (Tailored)"
            else:
                baseline_tailored_string = f"{tailored_filename.upper()} (Tailored from {args.keyword.upper()})"
            # prompt for inclusion, add ODV
            odv_baseline_rules = odv_query(found_rules, benchmark)
            baseline_output_file = open(f"{build_path}/{tailored_filename}.yaml", 'w')
            baseline_output_file.write(output_baseline(odv_baseline_rules, version_yaml["os"], baseline_tailored_string, benchmark, authors, full_title))
        else:
            baseline_output_file = open(f"{build_path}/{args.keyword}.yaml", 'w')
            baseline_output_file.write(output_baseline(found_rules, version_yaml["os"], baseline_tailored_string, benchmark, authors, full_title))
    
    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()
