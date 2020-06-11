#!/usr/bin/env python3
# filename: yaml-to-xls.py
# Document baseline in Microsoft Excel format
import io
import glob
import os
import yaml
import xlwt
import types
import collections
import plistlib
import argparse

from xlwt import Workbook
from string import Template
from itertools import groupby
from uuid import uuid4

# File path setup
file_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(file_dir)
# CCEs

def listToString(s):  
    
    # initialize an empty string 
    str1 = ""  
    
    # traverse in the string   
    for ele in s:  
        str1 += ele   
    
    # return string   
    return str1  

    
class PayloadDict:
    """Class to create and manipulate Configuration Profiles.
    The actual plist content can be accessed as a dictionary via the 'data' attribute.
    """
    def __init__(self, identifier, uuid=False, removal_allowed=False, description='',organization='', displayname=''):
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

        # An empty list for 'sub payloads' that we'll fill later
        self.data['PayloadContent'] = []

    
    def _updatePayload(self, payload_content_dict):
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
        payload_dict['PayloadIdentifier'] = "alacarte.macOS.FISMA.%s" % (
                                            payload_dict['PayloadUUID'])
            
        
        payload_dict['PayloadContent'] = payload_content_dict
        # Add the payload to the profile
        #print payload_dict
        self.data.update(payload_dict)

    def _addPayload(self, payload_content_dict):
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
        payload_dict['PayloadIdentifier'] = "alacarte.macOS.FISMA.%s" % (
                                            payload_dict['PayloadUUID'])
            
        
        payload_dict['PayloadContent'] = payload_content_dict
        # Add the payload to the profile
        #print payload_dict
        del payload_dict['PayloadContent']['PayloadType']
        self.data['PayloadContent'].append(payload_dict)


    def addNewPayload(self, payload_type, settings):
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
        payload_dict['PayloadIdentifier'] = "alacarte.macOS.FISMA.%s" % (
                                            payload_dict['PayloadUUID'])

    
        # Add the settings to the payload
        for setting in settings:
            for k,v in setting.items():
                payload_dict[k] = v
                
        
        # Add the payload to the profile
        #
        self.data['PayloadContent'].append(payload_dict)


    def addMCXPayload(self, settings):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        keys = settings[1]
        plist_dict = {}
        for key in keys.split():
            plist_dict[key] = settings[2]
        

        
        payload_dict = {}

        state = "Forced"
        domain = settings[0]

        # Boilerplate
        payload_dict[domain] = {}
        payload_dict[domain][state] = []
        payload_dict[domain][state].append({})
        payload_dict[domain][state][0]['mcx_preference_settings'] = plist_dict
        payload_dict['PayloadType'] = "com.apple.ManagedClient.preferences"


        self._addPayload(payload_dict)


    def finalizeAndSave(self, output_path):
        """Perform last modifications and save to an output plist.
        """
        writePlist(self.data, output_path)


def makeNewUUID():
    return str(uuid4())

def configProfile(rule):
    # default values
    organization = "macOS Security Compliance Project Working Group"
    displayname = "macOS FISMA Baseline settings"
    
    # File path setup
    file_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(file_dir)

    # import profile_manifests.plist
    manifests_file = os.path.join(parent_dir, 'includes', 'supported_payloads.yaml')
    with open(manifests_file) as r:
        manifests = yaml.load(r, Loader=yaml.SafeLoader)        

    # Output folder
    mobileconfig_output_path = os.path.join(parent_dir, 'build', 'mobileconfigs')
    

    profile_errors = []
    profile_types = {}
    


    # Read all rules in the section and output them

    
    payload_type = ''
    with open(rule) as r:
        rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    if rule_yaml['mobileconfig']:

        for payload_type, info in rule_yaml['mobileconfig_info'].items():
            try:
                if payload_type not in manifests['payloads_types']:
                    profile_errors.append(rule)
                    raise ValueError("{}: Payload Type is not supported".format(payload_type))
                else:  
                    pass
            except (KeyError, ValueError) as e:
                profile_errors.append(rule)
                print(e)
                pass

            try:
                if isinstance(info, list):
                    raise ValueError("Payload key is non-conforming")
                else:
                    pass
            except (KeyError, ValueError) as e:
                profile_errors.append(rule)
                print(e)
                pass
        
            
            if payload_type == "com.apple.ManagedClient.preferences":
                for payload_domain, settings in info.items():
                    for key, value in settings.items():
                        payload_settings = (payload_domain, key, value)
                        profile_types.setdefault(payload_type,[]).append(payload_settings)
            else:
                for profile_key, key_value in info.items():
                    payload_settings = {profile_key : key_value}
                    profile_types.setdefault(payload_type,[]).append(payload_settings)

    if len(profile_errors) > 0:
        print("There are errors in the following files, please correct the .yaml file(s)!")
        for error in profile_errors:
            print(error)

    # process the payloads from the yaml file and generate new config profile for each type
    for payload,settings in profile_types.items():
        mobileconfig_file_path=os.path.join(mobileconfig_output_path,payload + '.mobileconfig')
        identifier = payload + ".FISMA"
        description = "Configuration settings for the {} preference domain.".format(payload)
        
        newProfile = PayloadDict(identifier=identifier,
            uuid=False,
            removal_allowed=False,
            organization=organization,
            displayname=displayname,
            description=description)

        
        if payload == "com.apple.ManagedClient.preferences":
            for item in settings:
                newProfile.addMCXPayload(item)
        else:
            newProfile.addNewPayload(payload, settings)
                
        data = plistlib.dumps(newProfile.data).decode("utf-8")

        return data



parser = argparse.ArgumentParser(description='Given a profile, create an Excel Spreadsheet for documentation.')
parser.add_argument("baseline", default=None, help="Baseline YAML file used to create the guide.", type=argparse.FileType('rt'))
parser.add_argument("-o", "--output", default=None, help="Output file", type=argparse.FileType('wt'))

try:
    results = parser.parse_args()
    output_basename = os.path.basename(results.baseline.name)
    output_filename = os.path.splitext(output_basename)[0]
    output_file = "../build/{}.xls".format(output_filename)
    print ('Profile YAML:', results.baseline.name)
    print ('Output file:', output_file)
    
except IOError as msg:
    parser.error(str(msg))

profile_yaml = yaml.load(results.baseline, Loader=yaml.SafeLoader)

wb = Workbook()

sheet1 = wb.add_sheet('Sheet 1')
topWrap = xlwt.easyxf("align: vert top; alignment: wrap True")
top = xlwt.easyxf("align: vert top")
headers = xlwt.easyxf("font: bold on")
counter = 1
sheet1.write(0,0, "CCE",headers)
sheet1.write(0,1, "Rule ID",headers)
sheet1.write(0,2, "Title",headers)
sheet1.write(0,3, "Discussion",headers)
sheet1.write(0,4, "Mechanism",headers)
sheet1.write(0,5, "Check",headers)
sheet1.write(0,6, "Check Result",headers)
sheet1.write(0,7, "Fix",headers)
sheet1.write(0,8, "800-53r4",headers)
sheet1.write(0,9, "SRG",headers)
sheet1.write(0,10, "DISA STIG",headers)
sheet1.write(0,11, "CCI",headers)
sheet1.set_panes_frozen(True)
sheet1.set_horz_split_pos(1)
sheet1.set_vert_split_pos(2)


for sections in profile_yaml['profile']:
    for profile_rule in sections['rules']:
        for rule_file in glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
    
            if "srg" in rule_file or "supplemental" in rule_file:
                 continue

            with open(rule_file) as r:
                rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)

            check = rule_yaml['check']

            
            result = " "
            try:
                result = str(rule_yaml['result'])
            except KeyError:
                result = ""
            
            cce = ""
            try:
                cce = rule_yaml['references']['cce']
            except KeyError:
                cce = ""

            sheet1.write(counter,0, cce,top)
            sheet1.col(0).width = 256 * 15
            sheet1.write(counter,1, rule_yaml['id'],top)
            sheet1.col(1).width = 512 * 25
            sheet1.write(counter,2, rule_yaml['title'],top)
            sheet1.col(2).width = 600 * 30
            sheet1.write(counter,3, str(rule_yaml['discussion']),topWrap)
            sheet1.col(3).width = 700 * 35
            mechanism = "Manual"
            if "[source,bash]" in rule_yaml['fix']:
                mechanism = "Scipt"
            if "This is implemented by a Configuration Profile." in rule_yaml['fix']:
                mechanism = "Configuration Profile"
            if "inherent" in rule_file:
                mechanism = "The control cannot be configured out of compliance."
            if "permanent" in rule_file:
                mechanism = "The control is not able to be configure to meet the requirement.  It is recommended to implement a third-party solution to meet the control."
            if "not_applicable" in rule_file:
                mechanism = " The control is not applicable when configuring a macOS system."

            
            sheet1.write(counter,4,mechanism,top)
            sheet1.col(4).width = 256 * 25

            sheet1.write(counter,5, check,topWrap)
            sheet1.col(5).width = 750 * 50
            
            sheet1.write(counter,6,result,topWrap)
            sheet1.col(6).width = 256 * 25
            
            if rule_yaml['mobileconfig']:

                
                sheet1.write(counter,7,str(configProfile(rule_file)),topWrap)
            else:
                
                sheet1.write(counter,7, str(rule_yaml['fix']),topWrap)
            
            sheet1.col(7).width = 1000 * 50

            baseline_refs = (str(rule_yaml['references']['800-53r4'])).strip('[]\'')
            baseline_refs = baseline_refs.replace(", ","\n").replace("\'","")
            
            sheet1.write(counter,8, baseline_refs,topWrap)
            sheet1.col(8).width = 256 * 15
            
            srg_refs = (str(rule_yaml['references']['srg'])).strip('[]\'')
            srg_refs = srg_refs.replace(", ","\n").replace("\'","")
            
            sheet1.write(counter,9, srg_refs,topWrap)
            sheet1.col(9).width = 500 * 15
            
            disa_refs = (str(rule_yaml['references']['disa_stig'])).strip('[]\'')
            disa_refs = srg_refs.replace(", ","\n").replace("\'","")
            
            sheet1.write(counter,10, disa_refs,topWrap)
            sheet1.col(10).width = 500 * 15
            
            cci = (str(rule_yaml['references']['cci'])).strip('[]\'')
            cci = cci.replace(", ","\n").replace("\'","")
            
            sheet1.write(counter,11, cci,topWrap)
            sheet1.col(11).width = 400 * 15

            tall_style = xlwt.easyxf('font:height 640;') # 36pt

            sheet1.row(counter).set_style(tall_style)
            counter = counter + 1

wb.save(output_file)        
