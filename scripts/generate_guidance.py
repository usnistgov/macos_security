#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given baseline, and output guidance files
import types
import sys
import os.path
import collections
import plistlib
import xlwt
import io
import glob
import os
import yaml
import re
import argparse
import subprocess
from xlwt import Workbook
from string import Template
from itertools import groupby
from uuid import uuid4

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

    def create_mobileconfig(self):
        pass

    # Convert a list to AsciiDoc
def ulify(elements):
    string = "\n"
    for s in elements:
        string += "* " + str(s) + "\n"
    return string

def group_ulify(elements):
    string = "\n * "
    for s in elements:
        string += str(s) + ", "
    return string[:-2]


def group_ulify_comment(elements):
    string = "\n * "
    for s in elements:
        string += str(s) + ", "
    return string[:-2]


def get_check_code(check_yaml):
    try:
        check_string = check_yaml.split("[source,bash]")[1]
    except:
        return check_yaml
    #print check_string
    check_code = re.search('(?:----((?:.*?\r?\n?)*)----)+', check_string)
    #print(check_code.group(1).rstrip())
    return(check_code.group(1).strip())


def quotify(fix_code):
    string = fix_code.replace("'", "\'\"\'\"\'")
    string = string.replace("%", "%%")

    return string


def get_fix_code(fix_yaml):
    fix_string = fix_yaml.split("[source,bash]")[1]
    fix_code = re.search('(?:----((?:.*?\r?\n?)*)----)+', fix_string)
    return(fix_code.group(1))


def format_mobileconfig_fix(mobileconfig):
    """Takes a list of domains and setting from a mobileconfig, and reformats it for the output of the fix section of the guide.
    """
    rulefix = ""
    for domain, settings in mobileconfig.items():
        if domain == "com.apple.ManagedClient.preferences":
            rulefix = rulefix + \
                (f"NOTE: The following settings are in the ({domain}) payload. This payload requires the additional settings to be sub-payloads within, containing their their defined payload types.\n\n")
            rulefix = rulefix + format_mobileconfig_fix(settings)

        else:
            rulefix = rulefix + (
                f"Create a configuration profile containing the following keys in the ({domain}) payload type:\n\n")
            rulefix = rulefix + "[source,xml]\n----\n"
            for item in settings.items():
                rulefix = rulefix + (f"<key>{item[0]}</key>\n")

                if type(item[1]) == bool:
                    rulefix = rulefix + \
                        (f"<{str(item[1]).lower()}/>\n")
                elif type(item[1]) == list:
                    rulefix = rulefix + "<array>\n"
                    for setting in item[1]:
                        rulefix = rulefix + \
                            (f"    <string>{setting}</string>\n")
                    rulefix = rulefix + "</array>\n"
                elif type(item[1]) == int:
                    rulefix = rulefix + \
                        (f"<integer>{item[1]}</integer>\n")
                elif type(item[1]) == str:
                    rulefix = rulefix + \
                        (f"<string>{item[1]}</string>\n")

            rulefix = rulefix + "----\n\n"

    return rulefix

class PayloadDict:
    """Class to create and manipulate Configuration Profiles.
    The actual plist content can be accessed as a dictionary via the 'data' attribute.
    """

    def __init__(self, identifier, uuid=False, removal_allowed=False, description='', organization='', displayname=''):
        self.data = {}
        self.data['PayloadVersion'] = 1
        self.data['PayloadOrganization'] = organization
        if uuid:
            self.data['PayloadUUID'] = uuid
        else:
            self.data['PayloadUUID'] = makeNewUUID()
        if removal_allowed:
            self.data['PayloadRemovalDisallowed'] = False
        else:
            self.data['PayloadRemovalDisallowed'] = True
        self.data['PayloadType'] = 'Configuration'
        self.data['PayloadScope'] = 'System'
        self.data['PayloadDescription'] = description
        self.data['PayloadDisplayName'] = displayname
        self.data['PayloadIdentifier'] = identifier
        self.data['ConsentText'] = {"default": "THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER."}

        # An empty list for 'sub payloads' that we'll fill later
        self.data['PayloadContent'] = []

    def _updatePayload(self, payload_content_dict, baseline_name):
        """Update the profile with the payload settings. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        #description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadEnabled'] = True
        payload_dict['PayloadType'] = payload_content_dict['PayloadType']
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        payload_dict['PayloadContent'] = payload_content_dict
        # Add the payload to the profile
        self.data.update(payload_dict)

    def _addPayload(self, payload_content_dict, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        #description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadEnabled'] = True
        payload_dict['PayloadType'] = payload_content_dict['PayloadType']
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        payload_dict['PayloadContent'] = payload_content_dict
        # Add the payload to the profile
        #print payload_dict
        del payload_dict['PayloadContent']['PayloadType']
        self.data['PayloadContent'].append(payload_dict)

    def addNewPayload(self, payload_type, settings, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        #description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadEnabled'] = True
        payload_dict['PayloadType'] = payload_type
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        # Add the settings to the payload
        for setting in settings:
            for k, v in setting.items():
                payload_dict[k] = v

        # Add the payload to the profile
        #
        self.data['PayloadContent'].append(payload_dict)

    def addMCXPayload(self, settings, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        keys = settings[1]
        plist_dict = {}
        for key in keys.split():
            plist_dict[key] = settings[2]

        #description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        state = "Forced"
        domain = settings[0]

        # Boilerplate
        payload_dict[domain] = {}
        payload_dict[domain][state] = []
        payload_dict[domain][state].append({})
        payload_dict[domain][state][0]['mcx_preference_settings'] = plist_dict
        payload_dict['PayloadType'] = "com.apple.ManagedClient.preferences"

        self._addPayload(payload_dict, baseline_name)

    def finalizeAndSave(self, output_path):
        """Perform last modifications and save to an output plist.
        """

        plistlib.dump(self.data, output_path)
        print(f"Configuration profile written to {output_path.name}")


def makeNewUUID():
    return str(uuid4())


def concatenate_payload_settings(settings):
    """Takes a list of dictionaries, removed duplicate entries and concatenates an array of settings for the same key
    """
    settings_list = []
    settings_dict = {}
    for item in settings:
        for key, value in item.items():
            if isinstance(value, list):
                settings_dict.setdefault(key, []).append(value[0])
            else:
                settings_dict.setdefault(key, value)
        if item not in settings_list:
            settings_list.append(item)

    return [settings_dict]


def generate_profiles(baseline_name, build_path, parent_dir, baseline_yaml):
    """Generate the configuration profiles for the rules in the provided baseline YAML file
    """
    organization = "macOS Security Compliance Project"
    displayname = f"macOS {baseline_name} Baseline settings"

    # import profile_manifests.plist
    manifests_file = os.path.join(
        parent_dir, 'includes', 'supported_payloads.yaml')
    with open(manifests_file) as r:
        manifests = yaml.load(r, Loader=yaml.SafeLoader)

    # Output folder
    mobileconfig_output_path = os.path.join(
        f'{build_path}', 'mobileconfigs')
    if not (os.path.isdir(mobileconfig_output_path)):
        try:
            os.makedirs(mobileconfig_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  mobileconfig_output_path)

    # setup lists and dictionaries
    profile_errors = []
    profile_types = {}

    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule_yaml = get_rule_yaml(rule)
    
                if rule_yaml['mobileconfig']:
                    for payload_type, info in rule_yaml['mobileconfig_info'].items():
                        try:
                            if payload_type not in manifests['payloads_types']:
                                profile_errors.append(rule)
                                raise ValueError(
                                    "{}: Payload Type is not supported".format(payload_type))
                            else:
                                pass
                        except (KeyError, ValueError) as e:
                            profile_errors.append(rule)
                            #print(e)
                            pass

                        try:
                            if isinstance(info, list):
                                raise ValueError(
                                    "Payload key is non-conforming")
                            else:
                                pass
                        except (KeyError, ValueError) as e:
                            profile_errors.append(rule)
                            #print(e)
                            pass

                        if payload_type == "com.apple.ManagedClient.preferences":
                            for payload_domain, settings in info.items():
                                for key, value in settings.items():
                                    payload_settings = (
                                        payload_domain, key, value)
                                    profile_types.setdefault(
                                        payload_type, []).append(payload_settings)
                        else:
                            for profile_key, key_value in info.items():
                                payload_settings = {profile_key: key_value}
                                profile_types.setdefault(
                                    payload_type, []).append(payload_settings)

    if len(profile_errors) > 0:
        print("There are errors in the following files, please correct the .yaml file(s)!")
        for error in profile_errors:
            print(error)
    # process the payloads from the yaml file and generate new config profile for each type
    for payload, settings in profile_types.items():
        mobileconfig_file_path = os.path.join(
            mobileconfig_output_path, payload + '.mobileconfig')
        identifier = payload + f".{baseline_name}"
        description = "Configuration settings for the {} preference domain.".format(
            payload)

        newProfile = PayloadDict(identifier=identifier,
                                 uuid=False,
                                 removal_allowed=False,
                                 organization=organization,
                                 displayname=displayname,
                                 description=description)

        config_file = open(mobileconfig_file_path, "wb")

        if payload == "com.apple.ManagedClient.preferences":
            for item in settings:
                newProfile.addMCXPayload(item, baseline_name)
        # handle these payloads for array settings
        elif (payload == "com.apple.applicationaccess.new") or (payload == 'com.apple.systempreferences'):
            newProfile.addNewPayload(
                payload, concatenate_payload_settings(settings), baseline_name)
        else:
            newProfile.addNewPayload(payload, settings, baseline_name)

        newProfile.finalizeAndSave(config_file)
        config_file.close()

    print(f"""
    CAUTION: These configuration profiles are intended for evaluation in a TEST
    environment. Certain configuration profiles (Smartcards), when applied could 
    leave a system in a state where a user can no longer login with a password. 
    Please use caution when applying configuration settings to a system.
    
    NOTE: If an MDM is already being leveraged, many of these profile settings may
    be available through the vendor.
    """)

def generate_script(baseline_name, build_path, baseline_yaml):
    """Generates the zsh script from the rules in the baseline YAML
    """
    compliance_script_file = open(
        build_path + '/' + baseline_name + '_compliance.sh', 'w')

    check_function_string = ""
    fix_function_string = ""


    # create header of fix zsh script
    check_zsh_header = f"""#!/bin/zsh

##  This script will attempt to audit all of the settings based on the installed profile.

##  This script is provided as-is and should be fully tested on a system that is not in a production environment.  

###################  COMMANDS START BELOW THIS LINE  ###################

## Must be run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# get the currently logged in user
CURRENT_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {{ print $3 }}')

# configure colors for text
RED='\e[31m'
STD='\033[0;0;39m'
GREEN='\e[32m'
YELLOW='\e[33m'

# setup files
audit_plist="/Library/Preferences/org.{baseline_name}.audit.plist"
audit_log="/Library/Logs/{baseline_name}_baseline.log"

lastComplianceScan=$(defaults read /Library/Preferences/org.{baseline_name}.audit.plist lastComplianceCheck)

if [[ $lastComplianceScan == "" ]];then
    lastComplianceScan="No scans have been run"
fi

# pause function
pause(){{
vared -p "Press [Enter] key to continue..." -c fackEnterKey
}}

ask() {{
    while true; do

        if [ "${{2:-}}" = "Y" ]; then
            prompt="Y/n"
            default=Y
        elif [ "${{2:-}}" = "N" ]; then
            prompt="y/N"
            default=N
        else
            prompt="y/n"
            default=
        fi

        # Ask the question - use /dev/tty in case stdin is redirected from somewhere else
        printf "${{YELLOW}} $1 [$prompt] ${{STD}}"
        read REPLY
        
        # Default?
        if [ -z "$REPLY" ]; then
            REPLY=$default
        fi

        # Check if the reply is valid
        case "$REPLY" in
            Y*|y*) return 0 ;;
            N*|n*) return 1 ;;
        esac

    done
}}

# function to display menus
show_menus() {{
    clear
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"	
    echo "        M A I N - M E N U"
    echo "  macOS Security Compliance Tool"
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "Last compliance scan: $lastComplianceScan\n"
    echo "1. View Last Compliance Report"
    echo "2. Run New Compliance Scan"
    echo "3. Run Commands to remediate non-compliant settings"
    echo "4. Exit"
}}

# function to read options
read_options(){{
    local choice
    vared -p "Enter choice [ 1 - 4 ] " -c choice
    case $choice in
        1) view_report ;;
        2) run_scan ;;
        3) run_fix ;;
        4) exit 0;;
        *) echo -e "${{RED}}Error: please choose an option 1-4...${{STD}}" && sleep 1
    esac
}}

generate_report(){{
    non_compliant=0
    compliant=0

    results=$(/usr/libexec/PlistBuddy -c "Print" /Library/Preferences/org.{baseline_name}.audit.plist)

    while IFS= read -r line; do
        if [[ "$line" =~ "true" ]]; then
            non_compliant=$((non_compliant+1))
        fi
        if [[ "$line" =~ "false" ]]; then
            compliant=$((compliant+1))
        fi

    done <<< "$results"
    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    echo
    echo "Number of tests passed: ${{GREEN}}$compliant${{STD}}"
    echo "Number of test FAILED: ${{RED}}$non_compliant${{STD}}"
    echo "You are ${{YELLOW}}$percentage%${{STD}} percent compliant!"
    pause
}}

view_report(){{
    
    if [[ $lastComplianceScan == "" ]];then
        echo "no report to run, please run new scan"
        pause
    else
        generate_report
    fi
}}

run_scan(){{
# append to existing logfile
echo "$(date -u) Beginning {baseline_name} baseline scan" >> "$audit_log"

# write timestamp of last compliance check
defaults write "$audit_plist" lastComplianceCheck "$(date)"
    """

    #compliance_script_file.write(check_zsh_header)

    # Read all rules in the section and output the check functions
    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule_yaml = get_rule_yaml(rule)

                if rule_yaml['id'].startswith("supplemental"):
                    continue

                # grab the 800-53 controls
                try:
                    rule_yaml['references']['800-53r4']
                except KeyError:
                    nist_80053r4 = 'N/A'
                else:
                    nist_80053r4 = rule_yaml['references']['800-53r4']

            # group the controls
                nist_80053r4.sort()
                res = [list(i) for j, i in groupby(
                    nist_80053r4, lambda a: a.split('(')[0])]
                nist_controls = ''
                for i in res:
                    nist_controls += group_ulify(i)

                # print checks and result
                try:
                    check = rule_yaml['check']
                except KeyError:
                    print("no check found for {}".format(rule_yaml['id']))
                    continue
                try:
                    result = rule_yaml['result']
                except KeyError:
                    #print("no result found for {}".format(rule_yaml['id']))
                    continue

                if "integer" in result:
                    result_value = result['integer']
                elif "boolean" in result:
                    result_value = result['boolean']
                elif "string" in result:
                    result_value = result['string']
                else:
                    continue

                # write the checks
                zsh_check_text = """
#####----- Rule: {0} -----#####
## Addresses the following NIST 800-53 controls: {1}
echo 'Running the command to check the settings for: {0} ...' | tee -a "$audit_log"
result_value=$({2})
# expected result {3}

if [[ $result_value == "{4}" ]]; then
    echo "{0} passed..." | tee -a "$audit_log"
    defaults write "$audit_plist" {0} -bool NO
else
    echo "{0} FAILED..." | tee -a "$audit_log"
    defaults write "$audit_plist" {0} -bool YES
fi
    """.format(rule_yaml['id'], nist_controls.replace("\n", "\n#"), check.strip(), result, result_value)

                check_function_string = check_function_string + zsh_check_text

                # print fix and result
                try:
                    rule_yaml['fix']
                except KeyError:
                    fix_text = 'N/A'
                else:
                    fix_text = rule_yaml['fix'] or ["n/a"]

    # write the fixes
                if "[source,bash]" in fix_text:
                    zsh_fix_text = f"""
#####----- Rule: {rule_yaml['id']} -----#####
## Addresses the following NIST 800-53 controls: {nist_controls}

{rule_yaml['id']}_audit_score=$(defaults read $audit_plist {rule_yaml['id']})
if [[ ${rule_yaml['id']}_audit_score == 1 ]]; then
    ask '{rule_yaml['id']} - Run the command(s)-> {quotify(get_fix_code(rule_yaml['fix']).strip())} ' N
    if [[ $? == 0 ]]; then
        echo 'Running the command to configure the settings for: {rule_yaml['id']} ...' | tee -a "$audit_log"
        {get_fix_code(rule_yaml['fix']).strip()}
    fi
else
    echo 'Settings for: {rule_yaml['id']} already configured, continuing...' | tee -a "$audit_log"
fi
    """

                    fix_function_string = fix_function_string + zsh_fix_text

    # write the footer for the check functions
    zsh_check_footer = """
lastComplianceScan=$(defaults read "$audit_plist" lastComplianceCheck)
echo "Results written to $audit_plist"

pause
}

run_fix(){

if [[ ! -e "$audit_plist" ]]; then
    echo "Audit plist doesn't exist, please run Audit Check First" | tee -a "$audit_log"
    pause
    show_menus
    read_options
fi


ask 'THE SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER. WOULD YOU LIKE TO CONTINUE? ' N

if [[ $? != 0 ]]; then
    show_menus
    read_options
fi

# append to existing logfile
echo "$(date -u) Beginning FISMA fixes" >> "$audit_log"


    """

    # write the footer for the script
    zsh_fix_footer = """
}
while true; do
    show_menus
    read_options
done
    """

    #write out the compliance script
    compliance_script_file.write(check_zsh_header)
    compliance_script_file.write(check_function_string)
    compliance_script_file.write(zsh_check_footer)
    compliance_script_file.write(fix_function_string)
    compliance_script_file.write(zsh_fix_footer)

    print(f"Finished building {compliance_script_file.name}")

    # make the compliance script executable
    os.chmod(compliance_script_file.name, 0o755)

    #fix_script_file.close()
    compliance_script_file.close()

def get_rule_yaml(rule_file):
    """ Takes a rule file, checks for a custom version, and returns the yaml for the rule
    """
    if os.path.basename(rule_file) in glob.glob1('../custom/rules/', '*.yaml'):
        #print(f"Custom settings found for rule: {rule_file}")
        override_rule = os.path.join(
            '../custom/rules', os.path.basename(rule_file))
        with open(override_rule) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    else:
        with open(rule_file) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    return rule_yaml


def generate_xls(baseline_name, build_path, baseline_yaml):
    """Using the baseline yaml file, create an XLS document containing the YAML fields
    """

    baseline_rules = create_rules(baseline_yaml)

    # File path setup
    file_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(file_dir)

    # Output files
    xls_output_file = f"{build_path}/{baseline_name}.xls"


    wb = Workbook()

    sheet1 = wb.add_sheet('Sheet 1')
    topWrap = xlwt.easyxf("align: vert top; alignment: wrap True")
    top = xlwt.easyxf("align: vert top")
    headers = xlwt.easyxf("font: bold on")
    counter = 1
    sheet1.write(0, 0, "CCE", headers)
    sheet1.write(0, 1, "Rule ID", headers)
    sheet1.write(0, 2, "Title", headers)
    sheet1.write(0, 3, "Discussion", headers)
    sheet1.write(0, 4, "Mechanism", headers)
    sheet1.write(0, 5, "Check", headers)
    sheet1.write(0, 6, "Check Result", headers)
    sheet1.write(0, 7, "Fix", headers)
    sheet1.write(0, 8, "800-53r4", headers)
    sheet1.write(0, 9, "SRG", headers)
    sheet1.write(0, 10, "DISA STIG", headers)
    sheet1.write(0, 11, "CCI", headers)
    sheet1.set_panes_frozen(True)
    sheet1.set_horz_split_pos(1)
    sheet1.set_vert_split_pos(2)


    for rule in baseline_rules:
        if rule.rule_id.startswith("supplemental") or rule.rule_id.startswith("srg"):
            continue
                  
        sheet1.write(counter, 0, rule.rule_cce, top)
        sheet1.col(0).width = 256 * 15
        sheet1.write(counter, 1, rule.rule_id, top)
        sheet1.col(1).width = 512 * 25
        sheet1.write(counter, 2, rule.rule_title, top)
        sheet1.col(2).width = 600 * 30
        sheet1.write(counter, 3, str(rule.rule_discussion), topWrap)
        sheet1.col(3).width = 700 * 35
        mechanism = "Manual"
        if "[source,bash]" in rule.rule_fix:
            mechanism = "Scipt"
        if "This is implemented by a Configuration Profile." in rule.rule_fix:
            mechanism = "Configuration Profile"
        if "inherent" in rule.rule_tags:
            mechanism = "The control cannot be configured out of compliance."
        if "permanent" in rule.rule_tags:
            mechanism = "The control is not able to be configure to meet the requirement.  It is recommended to implement a third-party solution to meet the control."
        if "not_applicable" in rule.rule_tags:
            mechanism = " The control is not applicable when configuring a macOS system."

        sheet1.write(counter, 4, mechanism, top)
        sheet1.col(4).width = 256 * 25

        sheet1.write(counter, 5, rule.rule_check, topWrap)
        sheet1.col(5).width = 750 * 50

        sheet1.write(counter, 6, str(rule.rule_result_value), topWrap)
        sheet1.col(6).width = 256 * 25

        if rule.rule_mobileconfig:
            sheet1.write(counter, 7, format_mobileconfig_fix(
                rule.rule_mobileconfig_info), topWrap)
            #print(format_mobileconfig_fix(rule.rule_mobileconfig_info))

            # sheet1.write(counter, 7, str(
            #     configProfile(rule_file)), topWrap)
        else:
            sheet1.write(counter, 7, str(rule.rule_fix), topWrap)

        sheet1.col(7).width = 1000 * 50

        baseline_refs = (
            str(rule.rule_80053r4)).strip('[]\'')
        baseline_refs = baseline_refs.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 8, baseline_refs, topWrap)
        sheet1.col(8).width = 256 * 15

        srg_refs = (str(rule.rule_srg)).strip('[]\'')
        srg_refs = srg_refs.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 9, srg_refs, topWrap)
        sheet1.col(9).width = 500 * 15

        disa_refs = (str(rule.rule_disa_stig)).strip('[]\'')
        disa_refs = srg_refs.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 10, disa_refs, topWrap)
        sheet1.col(10).width = 500 * 15

        cci = (str(rule.rule_cci)).strip('[]\'')
        cci = cci.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 11, cci, topWrap)
        sheet1.col(11).width = 400 * 15

        tall_style = xlwt.easyxf('font:height 640;')  # 36pt

        sheet1.row(counter).set_style(tall_style)
        counter = counter + 1

    wb.save(xls_output_file)
    print(f"Finished building {xls_output_file}")

def create_rules(baseline_yaml):
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

    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule_yaml = get_rule_yaml(rule)

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
                                #print "expected reference '{}' is missing in key '{}' for rule{}".format(reference, key, rule)
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
    """configure the arguments used in the script, returns the parsed arguements
    """
    parser = argparse.ArgumentParser(
        description='Given a baseline, create guidance documents and files.')
    parser.add_argument("baseline", default=None,
                        help="Baseline YAML file used to create the guide.", type=argparse.FileType('rt'))
    parser.add_argument("-l", "--logo", default=None,
                        help="Full path to logo file to be inlcuded in the guide.", action="store")
    parser.add_argument("-p", "--profiles", default=None,
                        help="Generate configuration profiles for the rules.", action="store_true")
    parser.add_argument("-s", "--script", default=None,
                        help="Generate the compliance script for the rules.", action="store_true")
    parser.add_argument("-x", "--xls", default=None,
                        help="Generate the excel (xls) document for the rules.", action="store_true")
    return parser.parse_args()

def is_asciidoctor_installed():
    """Checks to see if the ruby gem for asciidoctor is installed
    """
    cmd = "gem list asciidoctor -i"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    
    return process.returncode


def is_asciidoctor_pdf_installed():
    """Checks to see if the ruby gem for asciidoctor-pdf is installed
    """
    cmd = "gem list asciidoctor-pdf -i"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    return process.returncode

def main():

    args = create_args()
    try:
        output_basename = os.path.basename(args.baseline.name)
        output_filename = os.path.splitext(output_basename)[0]
        baseline_name = os.path.splitext(output_basename)[0].capitalize()
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)

        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)

        if args.logo:
            logo = args.logo
        else:
            logo = "../../templates/images/nist.png"

        build_path = os.path.join(parent_dir, 'build', f'{baseline_name}')
        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")
        adoc_output_file = open(f"{build_path}/{output_filename}.adoc", 'w')
        print('Profile YAML:', args.baseline.name)
        print('Output path:', adoc_output_file.name)


    except IOError as msg:
        parser.error(str(msg))
    

    baseline_yaml = yaml.load(args.baseline, Loader=yaml.SafeLoader)


    # Setup AsciiDoc templates
    with open('../templates/adoc_rule.adoc') as adoc_rule_file:
        adoc_rule_template = Template(adoc_rule_file.read())

    with open('../templates/adoc_supplemental.adoc') as adoc_supplemental_file:
        adoc_supplemental_template = Template(adoc_supplemental_file.read())

    with open('../templates/adoc_rule_no_setting.adoc') as adoc_rule_no_setting_file:
        adoc_rule_no_setting_template = Template(adoc_rule_no_setting_file.read())

    with open('../templates/adoc_section.adoc') as adoc_section_file:
        adoc_section_template = Template(adoc_section_file.read())

    with open('../templates/adoc_header.adoc') as adoc_header_file:
        adoc_header_template = Template(adoc_header_file.read())

    with open('../templates/adoc_footer.adoc') as adoc_footer_file:
        adoc_footer_template = Template(adoc_footer_file.read())

    # Create header
    header_adoc = adoc_header_template.substitute(
        profile_title=baseline_yaml['title'],
        description=baseline_yaml['description'],
        html_header_title=baseline_yaml['title'],
        html_title=baseline_yaml['title'].split(':')[0],
        html_subtitle=baseline_yaml['title'].split(':')[1],
        logo=logo
    )

    # Output header
    adoc_output_file.write(header_adoc)
        

    # Create sections and rules
    for sections in baseline_yaml['profile']:
        section_yaml_file = sections['section'].lower() + '.yaml'
        #check for custom section
        if section_yaml_file in glob.glob1('../custom/sections/', '*.yaml'):
            print(f"Custom settings found for section: {sections['section']}")
            override_section = os.path.join(
                '../custom/sections', sections['section'] + '.yaml')
            with open(override_section) as r:
                section_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        else:
            with open('../sections/' + sections['section'] + '.yaml') as s:
                section_yaml = yaml.load(s, Loader=yaml.SafeLoader)

        # Read section info and output it

        section_adoc = adoc_section_template.substitute(
            section_name=section_yaml['name'],
            description=section_yaml['description']
        )

        adoc_output_file.write(section_adoc)

        # Read all rules in the section and output them

        for rule in sections['rules']:
            # print(rule)
            rule_path = glob.glob('../rules/*/{}.yaml'.format(rule))
            rule_file = (os.path.basename(rule_path[0]))

            #check for custom rule
            if rule_file in glob.glob1('../custom/rules/', '*.yaml'):
                print(f"Custom settings found for rule: {rule_file}")
                override_rule = os.path.join('../custom/rules', rule_file)
                with open(override_rule) as r:
                    rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
            else:
                with open(rule_path[0]) as r:
                    rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)

            # Determine if the references exist and set accordingly
            try:
                rule_yaml['references']['cci']
            except KeyError:
                cci = 'N/A'
            else:
                cci = ulify(rule_yaml['references']['cci'])

            try:
                rule_yaml['references']['cce']
            except KeyError:
                cce = 'N/A'
            else:
                cce = ulify(rule_yaml['references']['cce'])

            try:
                rule_yaml['references']['800-53r4']
            except KeyError:
                nist_80053r4 = 'N/A'
            else:
                #nist_80053r4 = ulify(rule_yaml['references']['800-53r4'])
                nist_80053r4 = rule_yaml['references']['800-53r4']

            try:
                rule_yaml['references']['disa_stig']
            except KeyError:
                disa_stig = 'N/A'
            else:
                disa_stig = ulify(rule_yaml['references']['disa_stig'])

            try:
                rule_yaml['references']['srg']
            except KeyError:
                srg = 'N/A'
            else:
                srg = ulify(rule_yaml['references']['srg'])

            try:
                rule_yaml['fix']
            except KeyError:
                rulefix = "No fix Found"
            else:
                rulefix = rule_yaml['fix']  # .replace('|', '\|')

            try:
                rule_yaml['tags']
            except KeyError:
                tags = 'none'
            else:
                tags = rule_yaml['tags']

            try:
                result = rule_yaml['result']
            except KeyError:
                result = 'N/A'

            if "integer" in result:
                result_value = result['integer']
                result_type = "integer"
            elif "boolean" in result:
                result_value = result['boolean']
                result_type = "boolean"
            elif "string" in result:
                result_value = result['string']
                result_type = "string"
            else:
                result_value = 'N/A'

            # deteremine if configprofile
            try:
                rule_yaml['mobileconfig']
            except KeyError:
                pass
            else:
                if rule_yaml['mobileconfig']:
                    rulefix = format_mobileconfig_fix(
                        rule_yaml['mobileconfig_info'])

            # process nist controls for grouping
            nist_80053r4.sort()
            res = [list(i) for j, i in groupby(
                nist_80053r4, lambda a: a.split('(')[0])]
            nist_controls = ''
            for i in res:
                nist_controls += group_ulify(i)

            if 'supplemental' in tags:
                rule_adoc = adoc_supplemental_template.substitute(
                    rule_title=rule_yaml['title'].replace('|', '\|'),
                    rule_id=rule_yaml['id'].replace('|', '\|'),
                    rule_discussion=rule_yaml['discussion'],
                )
            # elif ('permanent' in tags) or ('inherent' in tags) or ('n_a' in tags):
            #     rule_adoc = adoc_rule_no_setting_template.substitute(
            #         rule_title=rule_yaml['title'].replace('|', '\|'),
            #         rule_id=rule_yaml['id'].replace('|', '\|'),
            #         rule_discussion=rule_yaml['discussion'].replace('|', '\|'),
            #         rule_check=rule_yaml['check'],  # .replace('|', '\|'),
            #         rule_fix=rulefix,
            #         rule_80053r4=nist_controls,
            #         rule_disa_stig=disa_stig,
            #         rule_srg=srg
            #     )
            else:
                rule_adoc = adoc_rule_template.substitute(
                    rule_title=rule_yaml['title'].replace('|', '\|'),
                    rule_id=rule_yaml['id'].replace('|', '\|'),
                    rule_discussion=rule_yaml['discussion'].replace('|', '\|'),
                    rule_check=rule_yaml['check'],  # .replace('|', '\|'),
                    rule_fix=rulefix,
                    rule_cci=cci,
                    rule_80053r4=nist_controls,
                    rule_cce=cce,
                    rule_srg=srg,
                    rule_result=result_value
                )

            adoc_output_file.write(rule_adoc)

    # Create footer
    footer_adoc = adoc_footer_template.substitute(
    )

    # Output footer
    adoc_output_file.write(footer_adoc)
    
    if args.profiles:
        print("Generating configuration profiles...")
        generate_profiles(baseline_name, build_path, parent_dir, baseline_yaml)
    
    if args.script:
        print("Generating compliance script...")
        generate_script(baseline_name, build_path, baseline_yaml)
    
    if args.xls:
        print('Generating excel document...')
        generate_xls(baseline_name, build_path, baseline_yaml)

    if is_asciidoctor_installed() == 0:
        print('Generating HTML file from AsciiDoc...')
        cmd = f"/usr/local/bin/asciidoctor {adoc_output_file.name}"
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
    else:
        print("If you would like to generate the HTML file from the AsciiDoc file, install the ruby gem for asciidoctor")
    
    if is_asciidoctor_pdf_installed() == 0:
        print('Generating PDF file from AsciiDoc...')
        cmd = f"/usr/local/bin/asciidoctor-pdf {adoc_output_file.name}"
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
    else:
        print("If you would like to generate the PDF file from the AsciiDoc file, install the ruby gem for asciidoctor-pdf")

    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()
