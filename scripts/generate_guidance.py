#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given baseline, and output guidance files
import types
import sys
import os.path
import plistlib
import xlwt
import io
import glob
import os
import yaml
import re
import argparse
import subprocess
import logging
import tempfile
from xlwt import Workbook
from string import Template
from itertools import groupby
from uuid import uuid4
from collections import namedtuple


class MacSecurityRule():
    def __init__(self, title, rule_id, severity, discussion, check, fix, cci, cce, nist_controls, nist_171, disa_stig, srg, cis, custom_refs, tags, result_value, mobileconfig, mobileconfig_info, customized):
        self.rule_title = title
        self.rule_id = rule_id
        self.rule_severity = severity
        self.rule_discussion = discussion
        self.rule_check = check
        self.rule_fix = fix
        self.rule_cci = cci
        self.rule_cce = cce
        self.rule_80053r5 = nist_controls
        self.rule_800171 = nist_171
        self.rule_disa_stig = disa_stig
        self.rule_srg = srg
        self.rule_cis = cis
        self.rule_custom_refs = custom_refs
        self.rule_result_value = result_value
        self.rule_tags = tags
        self.rule_mobileconfig = mobileconfig
        self.rule_mobileconfig_info = mobileconfig_info
        self.rule_customized = customized

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
            rule_80053r5=self.rule_80053r5,
            rule_disa_stig=self.rule_disa_stig,
            rule_cis=self.rule_cis,
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

class AdocTemplate:
    def __init__(self, name, path, template_file):
        self.name = name
        self.path = path
        self.template_file = template_file

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
        """Perform last modifications and save to configuration profile.
        """
        plistlib.dump(self.data, output_path)
        print(f"Configuration profile written to {output_path.name}")

    def finalizeAndSavePlist(self, output_path):
        """Perform last modifications and save to an output plist.
        """
        output_file_path = output_path.name
        preferences_path = os.path.dirname(output_file_path)
        

        settings_dict = {}
        for i in self.data['PayloadContent']:
            if i['PayloadType'] == "com.apple.ManagedClient.preferences":
                for key, value in i['PayloadContent'].items():
                    domain=key
                    preferences_output_file = os.path.join(preferences_path, domain + ".plist")
                    if not os.path.exists(preferences_output_file):
                        with open(preferences_output_file, 'w'): pass
                    with open (preferences_output_file, 'rb') as fp:
                        try:
                            settings_dict = plistlib.load(fp)
                        except:
                            settings_dict = {}
                    with open(preferences_output_file, 'wb') as fp:
                        for setting in value['Forced']:
                            for key, value in setting['mcx_preference_settings'].items():
                                settings_dict[key] = value
                    
                        #preferences_output_path = open(preferences_output_file, 'wb')
                        plistlib.dump(settings_dict, fp)
                        print(f"Settings plist written to {preferences_output_file}")
                    settings_dict.clear()
                    try:
                        os.unlink(output_file_path)
                    except:
                        continue
            else:
                if os.path.exists(output_file_path):
                    with open (output_file_path, 'rb') as fp:
                        try:
                            settings_dict = plistlib.load(fp)
                        except:
                            settings_dict = {}
                for key,value in i.items():
                    if not key.startswith("Payload"):
                        settings_dict[key] = value
        
                plistlib.dump(settings_dict, output_path)
                print(f"Settings plist written to {output_path.name}")
            

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


def generate_profiles(baseline_name, build_path, parent_dir, baseline_yaml, signing, hash=''):
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
    unsigned_mobileconfig_output_path = os.path.join(
        f'{build_path}', 'mobileconfigs', 'unsigned')
    if not (os.path.isdir(unsigned_mobileconfig_output_path)):
        try:
            os.makedirs(unsigned_mobileconfig_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  unsigned_mobileconfig_output_path)
    
    if signing:
        signed_mobileconfig_output_path = os.path.join(
            f'{build_path}', 'mobileconfigs', 'signed')
        if not (os.path.isdir(signed_mobileconfig_output_path)):
            try:
                os.makedirs(signed_mobileconfig_output_path)
            except OSError:
                print("Creation of the directory %s failed" %
                    signed_mobileconfig_output_path)

    settings_plist_output_path = os.path.join(
        f'{build_path}', 'mobileconfigs', 'preferences')
    if not (os.path.isdir(settings_plist_output_path)):
        try:
            os.makedirs(settings_plist_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  settings_plist_output_path)
    # setup lists and dictionaries
    profile_errors = []
    profile_types = {}
    mount_controls = {}

    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            logging.debug(f"checking for rule file for {profile_rule}")
            if glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
                rule = glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True)[0]
                custom=True
                logging.debug(f"{rule}")
            elif glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule = glob.glob('../rules/*/{}.yaml'.format(profile_rule))[0]
                custom=False
                logging.debug(f"{rule}")

            #for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)) + glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
            rule_yaml = get_rule_yaml(rule, custom)
    
            if rule_yaml['mobileconfig']:
                for payload_type, info in rule_yaml['mobileconfig_info'].items():
                    valid = True
                    try:
                        if payload_type not in manifests['payloads_types']:
                            profile_errors.append(rule)
                            raise ValueError(
                                "{}: Payload Type is not supported".format(payload_type))
                        else:
                            pass
                    except (KeyError, ValueError) as e:
                        profile_errors.append(rule)
                        logging.debug(e)
                        valid = False

                    try:
                        if isinstance(info, list):
                            raise ValueError(
                                "Payload key is non-conforming")
                        else:
                            pass
                    except (KeyError, ValueError) as e:
                        profile_errors.append(rule)
                        logging.debug(e)
                        valid = False
                    
                    if valid:
                        if payload_type == "com.apple.systemuiserver":
                            for setting_key, setting_value in info['mount-controls'].items():
                                mount_controls[setting_key] = setting_value
                                payload_settings = {"mount-controls": mount_controls}
                                profile_types.setdefault(
                                    payload_type, []).append(payload_settings)
                        elif payload_type == "com.apple.ManagedClient.preferences":
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
        if payload.startswith("."):
            unsigned_mobileconfig_file_path = os.path.join(
                unsigned_mobileconfig_output_path, "com.apple" + payload + '.mobileconfig')
            settings_plist_file_path = os.path.join(
                settings_plist_output_path, "com.apple" + payload + '.plist')
            if signing:
                signed_mobileconfig_file_path = os.path.join(
                signed_mobileconfig_output_path, "com.apple" + payload + '.mobileconfig')
        else:
            unsigned_mobileconfig_file_path = os.path.join(
                unsigned_mobileconfig_output_path, payload + '.mobileconfig')
            settings_plist_file_path = os.path.join(
                settings_plist_output_path, payload + '.plist')
            if signing:
                signed_mobileconfig_file_path = os.path.join(
                signed_mobileconfig_output_path, payload + '.mobileconfig')
        identifier = payload + f".{baseline_name}"
        description = "Configuration settings for the {} preference domain.".format(
            payload)

        newProfile = PayloadDict(identifier=identifier,
                                 uuid=False,
                                 removal_allowed=False,
                                 organization=organization,
                                 displayname=displayname,
                                 description=description)

        

        if payload == "com.apple.ManagedClient.preferences":
            for item in settings:
                newProfile.addMCXPayload(item, baseline_name)
        # handle these payloads for array settings
        elif (payload == "com.apple.applicationaccess.new") or (payload == 'com.apple.systempreferences'):
            newProfile.addNewPayload(
                payload, concatenate_payload_settings(settings), baseline_name)
        else:
            newProfile.addNewPayload(payload, settings, baseline_name)

        if signing:
            unsigned_file_path=os.path.join(unsigned_mobileconfig_file_path)
            unsigned_config_file = open(unsigned_file_path, "wb")
            newProfile.finalizeAndSave(unsigned_config_file)
            settings_config_file = open(settings_plist_file_path, "wb")
            newProfile.finalizeAndSavePlist(settings_config_file)
            unsigned_config_file.close()
            # sign the profiles
            sign_config_profile(unsigned_file_path, signed_mobileconfig_file_path, hash)
            # delete the unsigned

        else:
            config_file = open(unsigned_mobileconfig_file_path, "wb")
            settings_config_file = open(settings_plist_file_path, "wb")
            newProfile.finalizeAndSave(config_file)
            newProfile.finalizeAndSavePlist(settings_config_file)
            config_file.close()
            
    print(f"""
    CAUTION: These configuration profiles are intended for evaluation in a TEST
    environment. Certain configuration profiles (Smartcards), when applied could 
    leave a system in a state where a user can no longer login with a password. 
    Please use caution when applying configuration settings to a system.
    
    NOTE: If an MDM is already being leveraged, many of these profile settings may
    be available through the vendor.
    """)

def default_audit_plist(baseline_name, build_path, baseline_yaml):
    """"Generate the default audit plist file to define exemptions
    """
    
    # Output folder
    plist_output_path = os.path.join(
        f'{build_path}', 'preferences')
    if not (os.path.isdir(plist_output_path)):
        try:
            os.makedirs(plist_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  plist_output_path)

    plist_file_path = os.path.join(
                plist_output_path, 'org.' + baseline_name + '.audit.plist')

    plist_file = open(plist_file_path, "wb")

    plist_dict = {}

    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            if profile_rule.startswith("supplemental"):
                continue
            plist_dict[profile_rule] = { "exempt": False }
    
    plistlib.dump(plist_dict, plist_file)


def generate_script(baseline_name, build_path, baseline_yaml, reference):
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

###################  Variables  ###################

pwpolicy_file=""

###################  COMMANDS START BELOW THIS LINE  ###################

## Must be run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# path to PlistBuddy
plb="/usr/libexec/PlistBuddy"

# get the currently logged in user
CURRENT_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {{ print $3 }}')
CURR_USER_UID=$(/usr/bin/id -u $CURRENT_USER)

# get system architecture
arch=$(/usr/bin/arch)

# configure colors for text
RED='\e[31m'
STD='\e[39m'
GREEN='\e[32m'
YELLOW='\e[33m'

# setup files
audit_plist_managed="/Library/Managed Preferences/org.{baseline_name}.audit.plist"

if [[ ! -e "$audit_plist_managed" ]];then
    audit_plist_managed="/Library/Preferences/org.{baseline_name}.audit.plist"
fi

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
    # if fix flag is passed, assume YES for everything
    if [[ $fix ]]; then
        return 0
    fi

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

# Generate the Compliant and Non-Compliant counts. Returns: Array (Compliant, Non-Compliant)
compliance_count(){{
    compliant=0
    non_compliant=0

    results=$(/usr/libexec/PlistBuddy -c "Print" /Library/Preferences/org.{baseline_name}.audit.plist)
    
    while IFS= read -r line; do
        if [[ "$line" =~ "finding = false" ]]; then
            compliant=$((compliant+1))
        fi
        if [[ "$line" =~ "finding = true" ]]; then
            non_compliant=$((non_compliant+1))
        fi
    done <<< "$results"
    
    # Enable output of just the compliant or non-compliant numbers. 
    if [[ $1 = "compliant" ]]
    then
        echo $compliant
    elif [[ $1 = "non-compliant" ]]
    then
        echo $non_compliant
    else # no matching args output the array
        array=($compliant $non_compliant)
        echo ${{array[@]}}
    fi
}}


generate_report(){{
    count=($(compliance_count))
    compliant=${{count[1]}}
    non_compliant=${{count[2]}}
    
    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    echo
    echo "Number of tests passed: ${{GREEN}}$compliant${{STD}}"
    echo "Number of test FAILED: ${{RED}}$non_compliant${{STD}}"
    echo "You are ${{YELLOW}}$percentage%${{STD}} percent compliant!"
    pause
}}

view_report(){{
    
    if [[ $lastComplianceScan == "No scans have been run" ]];then
        echo "no report to run, please run new scan"
        pause
    else
        generate_report
    fi
}}

# Designed for use with MDM - single unformatted output of the Compliance Report
generate_stats(){{
    count=($(compliance_count))
    compliant=${{count[1]}}
    non_compliant=${{count[2]}}
    
    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    echo "PASSED: $compliant FAILED: $non_compliant, $percentage percent compliant!"
}}

run_scan(){{
# append to existing logfile
if [[ $(/usr/bin/tail -n 1 "$audit_log" 2>/dev/null) = *"Remediation complete" ]]; then
 	echo "$(date -u) Beginning {baseline_name} baseline scan" >> "$audit_log"
else
 	echo "$(date -u) Beginning {baseline_name} baseline scan" > "$audit_log"
fi

#echo "$(date -u) Beginning {baseline_name} baseline scan" >> "$audit_log"

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID

# write timestamp of last compliance check
defaults write "$audit_plist" lastComplianceCheck "$(date)"
    """

    # Read all rules in the section and output the check functions
    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            logging.debug(f"checking for rule file for {profile_rule}")
            if glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
                rule = glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True)[0]
                custom=True
                logging.debug(f"{rule}")
            elif glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule = glob.glob('../rules/*/{}.yaml'.format(profile_rule))[0]
                custom=False
                logging.debug(f"{rule}")

            rule_yaml = get_rule_yaml(rule, custom)

            if rule_yaml['id'].startswith("supplemental"):
                continue
            if "manual" in rule_yaml['tags']:
                continue

            if "arm64" in rule_yaml['tags']:
                arch="arm64"
            elif "intel" in rule_yaml['tags']:
                arch="i386"
            else:
                arch=""
            
            # grab the 800-53 controls
            try:
                rule_yaml['references']['800-53r5']
            except KeyError:
                nist_80053r5 = 'N/A'
            else:
                nist_80053r5 = rule_yaml['references']['800-53r5']
            
            if reference == "default":
                log_reference_id = [rule_yaml['id']]
            else:
                try: 
                    rule_yaml['references'][reference]
                except KeyError:
                    try: 
                        rule_yaml['references']['custom'][reference]
                    except KeyError:
                        log_reference_id = [rule_yaml['id']]
                    else:
                        if isinstance(rule_yaml['references']['custom'][reference], list):
                            log_reference_id = rule_yaml['references']['custom'][reference] + [rule_yaml['id']]
                        else:
                            log_reference_id = [rule_yaml['references']['custom'][reference]] + [rule_yaml['id']]
                else:
                    if isinstance(rule_yaml['references'][reference], list):
                        log_reference_id = rule_yaml['references'][reference] + [rule_yaml['id']]
                    else:
                            log_reference_id = [rule_yaml['references'][reference]] + [rule_yaml['id']]
                            
                
        # group the controls
            if not nist_80053r5 == "N/A":
                nist_80053r5.sort()
                res = [list(i) for j, i in groupby(
                    nist_80053r5, lambda a: a.split('(')[0])]
                nist_controls = ''
                for i in res:
                    nist_controls += group_ulify(i)
            else:
                nist_controls = "N/A"

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
                result_value = str(result['boolean']).lower()
            elif "string" in result:
                result_value = result['string']
            else:
                continue

            # write the checks
            zsh_check_text = """
#####----- Rule: {0} -----#####
## Addresses the following NIST 800-53 controls: {1}
rule_arch="{6}"
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: {0} ...' | tee -a "$audit_log"
    unset result_value
    result_value=$({2}\n)
    # expected result {3}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print {0}:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print {0}:exempt_reason" "$audit_plist_managed" 2>/dev/null)


 
    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "{4}" ]]; then
            echo "$(date -u) {5} passed (Result: $result_value, Expected: "{3}")" | tee -a "$audit_log"
            defaults write "$audit_plist" {0} -dict-add finding -bool NO
        else
            echo "$(date -u) {5} failed (Result: $result_value, Expected: "{3}")" | tee -a "$audit_log"
            defaults write "$audit_plist" {0} -dict-add finding -bool YES
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "$(date -u) {5} has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
        defaults write "$audit_plist" {0} -dict-add finding -bool NO
        /bin/sleep 1
    fi
else
    echo "$(date -u) {5} does not apply to this architechture" | tee -a "$audit_log"
    defaults write "$audit_plist" {0} -dict-add finding -bool NO
fi
    """.format(rule_yaml['id'], nist_controls.replace("\n", "\n#"), check.strip(), str(result).lower(), result_value, ' '.join(log_reference_id), arch)

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
                nist_controls_commented = nist_controls.replace('\n', '\n#')
                zsh_fix_text = f"""
#####----- Rule: {rule_yaml['id']} -----#####
## Addresses the following NIST 800-53 controls: {nist_controls_commented}

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print {rule_yaml['id']}:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print {rule_yaml['id']}:exempt_reason" "$audit_plist_managed" 2>/dev/null)

{rule_yaml['id']}_audit_score=$($plb -c "print {rule_yaml['id']}:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ ${rule_yaml['id']}_audit_score == "true" ]]; then
        ask '{rule_yaml['id']} - Run the command(s)-> {quotify(get_fix_code(rule_yaml['fix']).strip())} ' N
        if [[ $? == 0 ]]; then
            echo 'Running the command to configure the settings for: {rule_yaml['id']} ...' | tee -a "$audit_log"
            {get_fix_code(rule_yaml['fix']).strip()}
        fi
    else
        echo 'Settings for: {rule_yaml['id']} already configured, continuing...' | tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) {rule_yaml['id']} has an exemption (Reason: "$exempt_reason")" | tee -a "$audit_log"
fi
    """

                fix_function_string = fix_function_string + zsh_fix_text

    # write the footer for the check functions
    zsh_check_footer = """
lastComplianceScan=$(defaults read "$audit_plist" lastComplianceCheck)
echo "Results written to $audit_plist"

if [[ ! $check ]];then
    pause
fi

}

run_fix(){

if [[ ! -e "$audit_plist" ]]; then
    echo "Audit plist doesn't exist, please run Audit Check First" | tee -a "$audit_log"

    if [[ ! $fix ]]; then
        pause
        show_menus
        read_options
    else 
        exit 1
    fi
fi

if [[ ! $fix ]]; then
    ask 'THE SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER. WOULD YOU LIKE TO CONTINUE? ' N

    if [[ $? != 0 ]]; then
        show_menus
        read_options
    fi
fi

# append to existing logfile
echo "$(date -u) Beginning remediation of non-compliant settings" >> "$audit_log"

# run mcxrefresh 
/usr/bin/mcxrefresh -u $CURR_USER_UID


    """

    # write the footer for the script
    zsh_fix_footer = """
echo "$(date -u) Remediation complete" >> "$audit_log"

}

# check for command line arguments, if --check or --fix, then just do them.
if (( # >= 2));then
    echo "Too many arguments. Usage: $0 [--check| --fix]"
    exit 1
fi

zparseopts -D -E -check=check -fix=fix -stats=stats -compliant=compliant -non_compliant=non_compliant

if [[ $check ]];then
    run_scan
elif [[ $fix ]];then    
    run_fix
elif [[ $stats ]];then    
    generate_stats
elif [[ $compliant ]];then    
    compliance_count "compliant"
elif [[ $non_compliant ]];then    
    compliance_count "non-compliant"
else
    while true; do
        show_menus
        read_options
    done
fi
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
        resulting_yaml['customized'] = ["customized rule"]
    
    # get original/default rule yaml for comparison
    with open(og_rule_path) as og:
        og_rule_yaml = yaml.load(og, Loader=yaml.SafeLoader)

    for yaml_field in og_rule_yaml:
        #print('processing field {} for rule {}'.format(yaml_field, file_name))
        if yaml_field == "references":
            if not 'references' in resulting_yaml:
                resulting_yaml['references'] = {}
            for ref in og_rule_yaml['references']:
                try:
                    if og_rule_yaml['references'][ref] == rule_yaml['references'][ref]:
                        resulting_yaml['references'][ref] = og_rule_yaml['references'][ref]
                    else:
                        resulting_yaml['references'][ref] = rule_yaml['references'][ref]
                except KeyError:
                    #  reference not found in original rule yaml, trying to use reference from custom rule
                    try:
                        resulting_yaml['references'][ref] = rule_yaml['references'][ref]
                    except KeyError:
                        resulting_yaml['references'][ref] = og_rule_yaml['references'][ref]
                try: 
                    if "custom" in rule_yaml['references']:
                        resulting_yaml['references']['custom'] = rule_yaml['references']['custom']
                        if 'customized' in resulting_yaml:
                            if 'customized references' not in resulting_yaml['customized']:
                                resulting_yaml['customized'].append("customized references")
                        else:
                            resulting_yaml['customized'] = ["customized references"]
                except:
                    pass
            
        else: 
            try:
                if og_rule_yaml[yaml_field] == rule_yaml[yaml_field]:
                    #print("using default data in yaml field {}".format(yaml_field))
                    resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
                else:
                    #print('using CUSTOM value for yaml field {} in rule {}'.format(yaml_field, file_name))
                    resulting_yaml[yaml_field] = rule_yaml[yaml_field]
                    if 'customized' in resulting_yaml:
                        resulting_yaml['customized'].append("customized {}".format(yaml_field))
                    else:
                        resulting_yaml['customized'] = ["customized {}".format(yaml_field)]
            except KeyError:
                resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]

    return resulting_yaml


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

    sheet1 = wb.add_sheet('Sheet 1', cell_overwrite_ok=True)
    topWrap = xlwt.easyxf("align: vert top; alignment: wrap True")
    top = xlwt.easyxf("align: vert top")
    headers = xlwt.easyxf("font: bold on")
    counter = 1
    column_counter = 16
    custom_ref_column = {}
    sheet1.write(0, 0, "CCE", headers)
    sheet1.write(0, 1, "Rule ID", headers)
    sheet1.write(0, 2, "Title", headers)
    sheet1.write(0, 3, "Discussion", headers)
    sheet1.write(0, 4, "Mechanism", headers)
    sheet1.write(0, 5, "Check", headers)
    sheet1.write(0, 6, "Check Result", headers)
    sheet1.write(0, 7, "Fix", headers)
    sheet1.write(0, 8, "800-53r5", headers)
    sheet1.write(0, 9, "800-171", headers)
    sheet1.write(0, 10, "SRG", headers)
    sheet1.write(0, 11, "DISA STIG", headers)
    sheet1.write(0, 12, "CIS Benchmark", headers)
    sheet1.write(0, 13, "CIS v8", headers)    
    sheet1.write(0, 14, "CCI", headers)
    sheet1.write(0, 15, "Modifed Rule", headers)
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
            mechanism = "Script"
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

        sheet1.write(counter, 5, rule.rule_check.replace("\|", "|"), topWrap)
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
            str(rule.rule_80053r5)).strip('[]\'')
        baseline_refs = baseline_refs.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 8, baseline_refs, topWrap)
        sheet1.col(8).width = 256 * 15

        nist171_refs = (
            str(rule.rule_800171)).strip('[]\'')
        nist171_refs = nist171_refs.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 9, nist171_refs, topWrap)
        sheet1.col(9).width = 256 * 15

        srg_refs = (str(rule.rule_srg)).strip('[]\'')
        srg_refs = srg_refs.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 10, srg_refs, topWrap)
        sheet1.col(10).width = 500 * 15

        disa_refs = (str(rule.rule_disa_stig)).strip('[]\'')
        disa_refs = disa_refs.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 11, disa_refs, topWrap)
        sheet1.col(11).width = 500 * 15

        cis = ""
        if rule.rule_cis != ['None']:
            for title, ref in rule.rule_cis.items():
                if title.lower() == "benchmark":
                    sheet1.write(counter, 12, ref, topWrap)
                    sheet1.col(12).width = 500 * 15
                if title.lower() == "controls v8":
                    cis = (str(ref).strip('[]\''))
                    cis = cis.replace(", ", "\n")
                    sheet1.write(counter, 13, cis, topWrap)
                    sheet1.col(13).width = 500 * 15

        cci = (str(rule.rule_cci)).strip('[]\'')
        cci = cci.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 14, cci, topWrap)
        sheet1.col(13).width = 400 * 15

        customized = (str(rule.rule_customized)).strip('[]\'')
        customized = customized.replace(", ", "\n").replace("\'", "")

        sheet1.write(counter, 15, customized, topWrap)
        sheet1.col(14).width = 400 * 15

        if rule.rule_custom_refs != ['None']:
            for title, ref in rule.rule_custom_refs.items():
                if title not in custom_ref_column:
                    custom_ref_column[title] = column_counter
                    column_counter = column_counter + 1
                    sheet1.write(0, custom_ref_column[title], title, headers)    
                    sheet1.col(custom_ref_column[title]).width = 512 * 25
                added_ref = (str(ref)).strip('[]\'')
                added_ref = added_ref.replace(", ", "\n").replace("\'", "")
                sheet1.write(counter, custom_ref_column[title], added_ref, topWrap)
                

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
            'discussion',
            'customized']
    references = ['disa_stig',
                  'cci',
                  'cce',
                  '800-53r5',
                  '800-171r2',
                  'cis',
                  'srg',
                  'custom']


    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            if glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
                rule = glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True)[0]
                custom=True
            elif glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule = glob.glob('../rules/*/{}.yaml'.format(profile_rule))[0]
                custom=False

            #for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)) + glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
            rule_yaml = get_rule_yaml(rule, custom)

            for key in keys:
                try:
                    rule_yaml[key]
                except:
                    #print("{} key missing ..for {}".format(key, rule))
                    rule_yaml.update({key: ""})
                if key == "references":
                    for reference in references:
                        try:
                            rule_yaml[key][reference]
                            #print("FOUND reference {} for key {} for rule {}".format(reference, key, rule))
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
                                        rule_yaml['references']['800-53r5'],
                                        rule_yaml['references']['800-171r2'],
                                        rule_yaml['references']['disa_stig'],
                                        rule_yaml['references']['srg'],
                                        rule_yaml['references']['cis'],
                                        rule_yaml['references']['custom'],
                                        rule_yaml['tags'],
                                        rule_yaml['result'],
                                        rule_yaml['mobileconfig'],
                                        rule_yaml['mobileconfig_info'],
                                        rule_yaml['customized']
                                        ))

    return all_rules

def create_args():
    """configure the arguments used in the script, returns the parsed arguements
    """
    parser = argparse.ArgumentParser(
        description='Given a baseline, create guidance documents and files.')
    parser.add_argument("baseline", default=None,
                        help="Baseline YAML file used to create the guide.", type=argparse.FileType('rt'))
    parser.add_argument("-c", "--clean", default=None,
                        help=argparse.SUPPRESS, action="store_true")
    parser.add_argument("-d", "--debug", default=None,
                        help=argparse.SUPPRESS, action="store_true")
    parser.add_argument("-l", "--logo", default=None,
                        help="Full path to logo file to be included in the guide.", action="store")
    parser.add_argument("-p", "--profiles", default=None,
                        help="Generate configuration profiles for the rules.", action="store_true")
    parser.add_argument("-r", "--reference", default=None,
                        help="Use the reference ID instead of rule ID for identification.")
    parser.add_argument("-s", "--script", default=None,
                        help="Generate the compliance script for the rules.", action="store_true")
    # add gary argument to include tags for XCCDF generation, with a nod to Gary the SCAP guru
    parser.add_argument("-g", "--gary", default=None,
                        help=argparse.SUPPRESS, action="store_true")
    parser.add_argument("-x", "--xls", default=None,
                        help="Generate the excel (xls) document for the rules.", action="store_true")
    parser.add_argument("-H", "--hash", default=None,
                        help="sign the configuration profiles with subject key ID (hash value without spaces)")
    return parser.parse_args()

def is_asciidoctor_installed():
    """Checks to see if the ruby gem for asciidoctor is installed
    """
    #cmd = "gem list asciidoctor -i"
    cmd = "which asciidoctor"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    
    # return path to asciidoctor
    return output.decode("utf-8").strip()


def is_asciidoctor_pdf_installed():
    """Checks to see if the ruby gem for asciidoctor-pdf is installed
    """
    #cmd = "gem list asciidoctor-pdf -i"
    cmd = "which asciidoctor-pdf"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    return output.decode("utf-8").strip()

def verify_signing_hash(hash):
    """Attempts to validate the existence of the certificate provided by the hash
    """
    with tempfile.NamedTemporaryFile(mode="w") as in_file:
        unsigned_tmp_file_path=in_file.name
        in_file.write("temporary file for signing")
    
        cmd = f"security cms -S -Z {hash} -i {unsigned_tmp_file_path}"
        FNULL = open(os.devnull, 'w')
        process = subprocess.Popen(cmd.split(), stdout=FNULL, stderr=FNULL)
        output, error = process.communicate()
    if process.returncode == 0:
        return True
    else:
        return False
        
def sign_config_profile(in_file, out_file, hash):
    """Signs the configuration profile using the identity associated with the provided hash
    """
    cmd = f"security cms -S -Z {hash} -i {in_file} -o {out_file}"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(f"Signed Configuration profile written to {out_file}")
    return output.decode("utf-8")

def parse_custom_references(reference):
    string = "\n"
    for item in reference:
        if isinstance(reference[item], list):
            string += "!" + str(item) + "\n!\n"
            for i in reference[item]:
                string += "* " + str(i) + "\n"
        else:
            string += "!" + str(item) + "!* " + str(reference[item]) + "\n"
    return string

def parse_cis_references(reference):
    string = "\n"
    for item in reference:
        if isinstance(reference[item], list):
            string += "!CIS " + str(item).title() + "\n!\n"
            string += "* "
            for i in reference[item]:
                string += str(i) + ", "
            string = string[:-2] + "\n"
        else:
            string += "!" + str(item) + "!* " + str(reference[item]) + "\n"
    return string


def main():

    args = create_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    try:
        output_basename = os.path.basename(args.baseline.name)
        output_filename = os.path.splitext(output_basename)[0]
        baseline_name = os.path.splitext(output_basename)[0]#.capitalize()
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)

        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)

        if args.logo:
            logo = args.logo
        else:
            logo = "../../templates/images/mscp_banner.png"

        build_path = os.path.join(parent_dir, 'build', f'{baseline_name}')
        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")
        adoc_output_file = open(f"{build_path}/{output_filename}.adoc", 'w')
        print('Profile YAML:', args.baseline.name)
        print('Output path:', adoc_output_file.name)

        if args.hash:
            signing = True
            if not verify_signing_hash(args.hash):
                sys.exit('Cannot use the provided hash to sign.  Please make sure you provide the subject key ID hash from an installed certificate')
        else:
            signing = False

        if args.reference:
            use_custom_reference = True
            log_reference = args.reference
        else:
            log_reference = "default"
            use_custom_reference = False 

    except IOError as msg:
        parser.error(str(msg))
    

    baseline_yaml = yaml.load(args.baseline, Loader=yaml.SafeLoader)
    version_file = os.path.join(parent_dir, "VERSION.yaml")
    with open(version_file) as r:
        version_yaml = yaml.load(r, Loader=yaml.SafeLoader)

    adoc_templates = [ "adoc_rule", 
                    "adoc_supplemental", 
                    "adoc_rule_no_setting", 
                    "adoc_rule_custom_refs",
                    "adoc_section", 
                    "adoc_header", 
                    "adoc_footer", 
                    "adoc_foreword",
                    "adoc_scope", 
                    "adoc_authors", 
                    "adoc_acronyms", 
                    "adoc_additional_docs"
    ]
    adoc_templates_dict = {}

    for template in adoc_templates:
        # custom template exists
        if template + ".adoc" in glob.glob1('../custom/templates/', '*.adoc'):
            print(f"Custom template found for : {template}")
            adoc_templates_dict[template] = f"../custom/templates/{template}.adoc"
        else:
            adoc_templates_dict[template] = f"../templates/{template}.adoc"
    
    # Setup AsciiDoc templates
    with open(adoc_templates_dict['adoc_rule']) as adoc_rule_file:
        adoc_rule_template = Template(adoc_rule_file.read())

    with open(adoc_templates_dict['adoc_supplemental']) as adoc_supplemental_file:
        adoc_supplemental_template = Template(adoc_supplemental_file.read())

    with open(adoc_templates_dict['adoc_rule_no_setting']) as adoc_rule_no_setting_file:
        adoc_rule_no_setting_template = Template(adoc_rule_no_setting_file.read())
    
    with open(adoc_templates_dict['adoc_rule_custom_refs']) as adoc_rule_custom_refs_file:
        adoc_rule_custom_refs_template = Template(adoc_rule_custom_refs_file.read())

    with open(adoc_templates_dict['adoc_section']) as adoc_section_file:
        adoc_section_template = Template(adoc_section_file.read())

    with open(adoc_templates_dict['adoc_header']) as adoc_header_file:
        adoc_header_template = Template(adoc_header_file.read())

    with open(adoc_templates_dict['adoc_footer']) as adoc_footer_file:
        adoc_footer_template = Template(adoc_footer_file.read())
    
    with open(adoc_templates_dict['adoc_foreword']) as adoc_foreword_file:
        adoc_foreword_template = adoc_foreword_file.read() + "\n"

    with open(adoc_templates_dict['adoc_scope']) as adoc_scope_file:
        adoc_scope_template = Template(adoc_scope_file.read() +"\n")
    
    with open(adoc_templates_dict['adoc_authors']) as adoc_authors_file:
        adoc_authors_template = Template(adoc_authors_file.read() + "\n")

    with open(adoc_templates_dict['adoc_acronyms']) as adoc_acronyms_file:
        adoc_acronyms_template = adoc_acronyms_file.read() + "\n"

    with open(adoc_templates_dict['adoc_additional_docs']) as adoc_additional_docs_file:
        adoc_additional_docs_template = adoc_additional_docs_file.read() + "\n"

    # set tag attribute
    if args.gary:
        adoc_tag_show=":show_tags:"
    else:
        adoc_tag_show=":show_tags!:"

    if "STIG" in baseline_yaml['title'].upper():
        adoc_STIG_show=":show_STIG:"
    else:
        adoc_STIG_show=":show_STIG!:"

    if "CIS" in baseline_yaml['title'].upper():
        adoc_cis_show=":show_cis:"
    else:
        adoc_cis_show=":show_cis!:"

    if "800" in baseline_yaml['title']:
         adoc_171_show=":show_171:"
    else:
         adoc_171_show=":show_171!:"

    # Create header
    header_adoc = adoc_header_template.substitute(
        profile_title=baseline_yaml['title'],
        description=baseline_yaml['description'],
        html_header_title=baseline_yaml['title'],
        html_title=baseline_yaml['title'].split(':')[0],
        html_subtitle=baseline_yaml['title'].split(':')[1],
        logo=logo,
        tag_attribute=adoc_tag_show,
        nist171_attribute=adoc_171_show,
        stig_attribute=adoc_STIG_show,
        cis_attribute=adoc_cis_show,
        version=version_yaml['version'],
        os_version=version_yaml['os'],
        release_date=version_yaml['date']
    )

    # Create scope
    scope_adoc = adoc_scope_template.substitute(
        scope_description=baseline_yaml['description']
    )

    # Create author
    authors_adoc = adoc_authors_template.substitute(
        authors_list=baseline_yaml['authors']
    )

    # Output header
    adoc_output_file.write(header_adoc)

    # write foreword, authors, acronyms, supporting docs
    adoc_output_file.write(adoc_foreword_template)
    adoc_output_file.write(scope_adoc)
    adoc_output_file.write(authors_adoc)
    adoc_output_file.write(adoc_acronyms_template)
    adoc_output_file.write(adoc_additional_docs_template)

        

    # Create sections and rules
    for sections in baseline_yaml['profile']:
        section_yaml_file = sections['section'].lower() + '.yaml'
        #check for custom section
        if section_yaml_file in glob.glob1('../custom/sections/', '*.yaml'):
            #print(f"Custom settings found for section: {sections['section']}")
            override_section = os.path.join(
                f'../custom/sections/{section_yaml_file}')
            with open(override_section) as r:
                section_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        else:
            with open(f'../sections/{section_yaml_file}') as s:
                section_yaml = yaml.load(s, Loader=yaml.SafeLoader)

        # Read section info and output it

        section_adoc = adoc_section_template.substitute(
            section_name=section_yaml['name'],
            description=section_yaml['description']
        )

        adoc_output_file.write(section_adoc)

        # Read all rules in the section and output them

        for rule in sections['rules']:
            logging.debug(f'processing rule id: {rule}')
            rule_path = glob.glob('../rules/*/{}.yaml'.format(rule))
            if not rule_path:
                print(f"Rule file not found in library, checking in custom folder for rule: {rule}")
                rule_path = glob.glob('../custom/rules/**/{}.yaml'.format(rule), recursive=True)
            try:
                rule_file = (os.path.basename(rule_path[0]))
            except IndexError:
                logging.debug(f'defined rule {rule} does not have valid yaml file, check that rule ID and filename match.')

            #check for custom rule
            if glob.glob('../custom/rules/**/{}'.format(rule_file), recursive=True):
                print(f"Custom settings found for rule: {rule_file}")
                #override_rule = glob.glob('../custom/rules/**/{}'.format(rule_file), recursive=True)[0]
                rule_location = glob.glob('../custom/rules/**/{}'.format(rule_file), recursive=True)[0]
                custom=True
            else:
                rule_location = rule_path[0]
                custom=False
            
            rule_yaml = get_rule_yaml(rule_location, custom)

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
                cce = '- N/A'
            else:
                cce = ulify(rule_yaml['references']['cce'])

            try:
                rule_yaml['references']['800-53r5']
            except KeyError:
                nist_80053r5 = 'N/A'
            else:
                nist_80053r5 = rule_yaml['references']['800-53r5']
            
            try:
                rule_yaml['references']['800-171r2']
            except KeyError:
                nist_800171 = '- N/A'
            else:
                nist_800171 = ulify(rule_yaml['references']['800-171r2'])

            try:
                rule_yaml['references']['disa_stig']
            except KeyError:
                disa_stig = '- N/A'
            else:
                disa_stig = ulify(rule_yaml['references']['disa_stig'])

            try:
                rule_yaml['references']['cis']
            except KeyError:
                cis = '- N/A'
            else:
                cis = parse_cis_references(rule_yaml['references']['cis'])

            try:
                rule_yaml['references']['srg']
            except KeyError:
                srg = '- N/A'
            else:
                srg = ulify(rule_yaml['references']['srg'])

            try:
                rule_yaml['references']['custom']
            except KeyError:
                custom_refs = ''
            else:
                custom_refs = parse_custom_references(rule_yaml['references']['custom'])

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
                tags = ulify(rule_yaml['tags'])

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

            # determine if configprofile
            try:
                rule_yaml['mobileconfig']
            except KeyError:
                pass
            else:
                if rule_yaml['mobileconfig']:
                    rulefix = format_mobileconfig_fix(
                        rule_yaml['mobileconfig_info'])

            # process nist controls for grouping
            if not nist_80053r5 == "N/A":
                nist_80053r5.sort()
                res = [list(i) for j, i in groupby(
                    nist_80053r5, lambda a: a.split('(')[0])]
                nist_controls = ''
                for i in res:
                    nist_controls += group_ulify(i)
            else:
                nist_controls = "- N/A"

            if 'supplemental' in tags:
                rule_adoc = adoc_supplemental_template.substitute(
                    rule_title=rule_yaml['title'].replace('|', '\|'),
                    rule_id=rule_yaml['id'].replace('|', '\|'),
                    rule_discussion=rule_yaml['discussion'],
                )
            elif ('permanent' in tags) or ('inherent' in tags) or ('n_a' in tags):
                rule_adoc = adoc_rule_no_setting_template.substitute(
                    rule_title=rule_yaml['title'].replace('|', '\|'),
                    rule_id=rule_yaml['id'].replace('|', '\|'),
                    rule_discussion=rule_yaml['discussion'].replace('|', '\|'),
                    rule_check=rule_yaml['check'],  # .replace('|', '\|'),
                    rule_fix=rulefix,
                    rule_80053r5=nist_controls,
                    rule_800171=nist_800171,
                    rule_disa_stig=disa_stig,
                    rule_cis=cis,
                    rule_cce=cce,
                    rule_tags=tags,
                    rule_srg=srg
                )
            elif custom_refs:
                rule_adoc = adoc_rule_custom_refs_template.substitute(
                    rule_title=rule_yaml['title'].replace('|', '\|'),
                    rule_id=rule_yaml['id'].replace('|', '\|'),
                    rule_discussion=rule_yaml['discussion'],#.replace('|', '\|'),
                    rule_check=rule_yaml['check'],  # .replace('|', '\|'),
                    rule_fix=rulefix,
                    rule_cci=cci,
                    rule_80053r5=nist_controls,
                    rule_800171=nist_800171,
                    rule_disa_stig=disa_stig,
                    rule_cis=cis,
                    rule_cce=cce,
                    rule_custom_refs=custom_refs,
                    rule_tags=tags,
                    rule_srg=srg,
                    rule_result=result_value
                )
            else:
                rule_adoc = adoc_rule_template.substitute(
                    rule_title=rule_yaml['title'].replace('|', '\|'),
                    rule_id=rule_yaml['id'].replace('|', '\|'),
                    rule_discussion=rule_yaml['discussion'].replace('|', '\|'),
                    rule_check=rule_yaml['check'],  # .replace('|', '\|'),
                    rule_fix=rulefix,
                    rule_cci=cci,
                    rule_80053r5=nist_controls,
                    rule_800171=nist_800171,
                    rule_disa_stig=disa_stig,
                    rule_cis=cis,
                    rule_cce=cce,
                    rule_tags=tags,
                    rule_srg=srg,
                    rule_result=result_value
                )

            adoc_output_file.write(rule_adoc)

    # Create footer
    footer_adoc = adoc_footer_template.substitute(
    )

    # Output footer
    adoc_output_file.write(footer_adoc)
    adoc_output_file.close()
    
    if args.profiles:
        print("Generating configuration profiles...")
        generate_profiles(baseline_name, build_path, parent_dir, baseline_yaml, signing, args.hash)
    
    if args.script:
        print("Generating compliance script...")
        generate_script(baseline_name, build_path, baseline_yaml, log_reference)
        default_audit_plist(baseline_name, build_path, baseline_yaml)
    
    if args.xls:
        print('Generating excel document...')
        generate_xls(baseline_name, build_path, baseline_yaml)

    asciidoctor_path = is_asciidoctor_installed()
    if asciidoctor_path != "":
        print('Generating HTML file from AsciiDoc...')
        cmd = f"{asciidoctor_path} \'{adoc_output_file.name}\'"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        process.communicate()
    else:
        print("If you would like to generate the HTML file from the AsciiDoc file, install the ruby gem for asciidoctor")
    
    asciidoctorPDF_path = is_asciidoctor_pdf_installed()

    # Don't create PDF if we are generating SCAP
    if not args.gary:
        asciidoctorPDF_path = is_asciidoctor_pdf_installed()
        if asciidoctorPDF_path != "":
            print('Generating PDF file from AsciiDoc...')
            cmd = f"{asciidoctorPDF_path} \'{adoc_output_file.name}\'"
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            process.communicate()
        else:
            print("If you would like to generate the PDF file from the AsciiDoc file, install the ruby gem for asciidoctor-pdf")

    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()
