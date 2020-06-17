#!/usr/bin/env python3
# filename: script_generator.py
# description: Create a zsh script to apply the "fix" commands for every rule

import io
import glob
import os
import yaml
import re
import plistlib
import argparse
from string import Template
from itertools import groupby

# Convert a list to AsciiDoc
def group_ulify(elements):
    string = "\n## "
    for s in elements:
        string += str(s) + ", "
    return string[:-2]

def get_check_code(check_yaml):
    try:
        check_string = check_yaml.split("[source,bash]")[1]
    except:
        return check_yaml
    #print check_string
    check_code = re.search('(?:----((?:.*?\r?\n?)*)----)+',check_string)
    print(check_code.group(1).rstrip())
    return(check_code.group(1).strip())

def quotify(fix_code):
    string = fix_code.replace("'", "\'\"\'\"\'")
    string = string.replace("%", "%%")

    return string

def get_fix_code(fix_yaml):
    fix_string = fix_yaml.split("[source,bash]")[1]
    fix_code = re.search('(?:----((?:.*?\r?\n?)*)----)+', fix_string)
    return(fix_code.group(1))
    
# File path setup
file_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(file_dir)


parser = argparse.ArgumentParser(description='Given a baseline, create a compliance script.')
parser.add_argument("baseline", default=None, help="Basline YAML file used to generate the script.", type=argparse.FileType('rt'))



try:
    results = parser.parse_args()
    print ('Profile YAML:', results.baseline.name)
except IOError as msg:
    parser.error(str(msg))

profile_yaml = yaml.load(results.baseline, Loader=yaml.SafeLoader)
profile_name = results.baseline.name.replace(".yaml","")
profile_name = profile_name.replace("../baselines/","")

# Output files
#sp80053_output_file = open(parent_dir + '/build/'+profile_name+'_controls.txt', 'w')
compliance_script_file = open(parent_dir + '/build/'+profile_name+'_compliance.sh', 'w')
#sp80053_controls = []

check_function_string = ""
fix_function_string = ""



# create header of fix zsh script
check_zsh_header=f"""#!/bin/zsh

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
audit_plist="/Library/Preferences/org.{profile_name}.audit.plist"
audit_log="/Library/Logs/{profile_name}_baseline.log"

lastComplianceScan=$(defaults read /Library/Preferences/org.{profile_name}.audit.plist lastComplianceCheck)

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

	results=$(/usr/libexec/PlistBuddy -c "Print" /Library/Preferences/org.{profile_name}.audit.plist)

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
echo "$(date -u) Beginning {profile_name} baseline scan" >> "$audit_log"

# write timestamp of last compliance check
defaults write "$audit_plist" lastComplianceCheck "$(date)"
"""

#compliance_script_file.write(check_zsh_header)

# Read all rules in the section and output the check functions
for sections in profile_yaml['profile']:
    for profile_rule in sections['rules']:
        for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
            rule_file = (os.path.basename(rule))

            #check for custom rule
            if rule_file in glob.glob1('../custom/rules/', '*.yaml'):
                print(f"Custom settings found for rule: {rule_file}")
                override_rule = os.path.join('../custom/rules', rule_file)
                with open(override_rule) as r:
                    rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
            else:
                with open(rule) as r:
                    rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)


            if rule_yaml['id'].startswith("supplemental"):
                #print "supplemental"
                continue

            
            # grab the 800-53 controls
            try:
                rule_yaml['references']['800-53r4']
            except KeyError:
                nist_80053r4 = 'N/A'
            else:
                nist_80053r4 = rule_yaml['references']['800-53r4']
                #sp80053_controls.extend(rule_yaml['references']['800-53r4'])
            
            
        # group the controls
            nist_80053r4.sort()
            res = [list(i) for j, i in groupby(nist_80053r4, lambda a: a.split('(')[0])]
            nist_controls = ''
            for i in res:
                nist_controls += group_ulify(i)

            
            # print checks and result
            try:
                check=rule_yaml['check']
            except KeyError:
                print("no check found for {}".format(rule_yaml['id']))
                continue
            try:
                result=rule_yaml['result']
            except KeyError:
                #print("no result found for {}".format(rule_yaml['id']))
                continue
            

            if "integer" in result:
                result_value=result['integer']
            elif "boolean" in result:
                result_value=result['boolean']
            elif "string" in result:
                result_value=result['string']
            else:
                continue
        
            
            # write the checks
            zsh_check_text="""
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
""".format(rule_yaml['id'], nist_controls, check.strip(), result, result_value) 

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
zsh_fix_footer="""
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



# sp80053_controls = list( dict.fromkeys(sp80053_controls))
# sp80053_controls.sort()

# sp80053_output_file.writelines("%s\n" % control for control in sp80053_controls)

# make the compliance script executable
os.chmod(compliance_script_file.name, 0o755)

#fix_script_file.close()
compliance_script_file.close()
#sp80053_output_file.close()
