#!/usr/bin/env python3
# filename: profile_generator.py
# description: Creates .mobileconfig files for payloads from yaml rules

import glob
import yaml
import types
import sys
import os
import os.path
import collections
import argparse
import plistlib
from uuid import uuid4

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
        self.data['ConsentText'] = { "default" : "THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER."}

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
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"
            
        
        payload_dict['PayloadContent'] = payload_content_dict
        # Add the payload to the profile
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
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"
            
        
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
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

    
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


        self._addPayload(payload_dict)


    def finalizeAndSave(self, output_path):
        """Perform last modifications and save to an output plist.
        """
        
        plistlib.dump(self.data, output_path)

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



def main():
    global baseline_name
    
    # parse the arguments
    parser = argparse.ArgumentParser(
        description='Given a baseline, create mobileconfig files for a given baseline.')
    parser.add_argument("baseline", default=None,
                        help="Baseline YAML file used to create the guide.", type=argparse.FileType('rt'))

    try:
        results = parser.parse_args()
        print('Profile YAML:', results.baseline.name)
    except IOError as msg:
        parser.error(str(msg))
    
    # get the name of the baseline being used
    baseline_basename = os.path.basename(results.baseline.name)
    baseline_name = os.path.splitext(baseline_basename)[0].capitalize()
    
    # default values
    organization = "macOS Security Compliance Project"
    displayname = f"macOS {baseline_name} Baseline settings"
    
    # File path setup
    file_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(file_dir)

    # import profile_manifests.plist
    manifests_file = os.path.join(parent_dir, 'includes', 'supported_payloads.yaml')
    with open(manifests_file) as r:
        manifests = yaml.load(r, Loader=yaml.SafeLoader)        

    # Output folder
    mobileconfig_output_path = os.path.join(parent_dir, 'build', 'mobileconfigs')
    if not (os.path.isdir(mobileconfig_output_path)):
        try:
            os.mkdir(mobileconfig_output_path)
        except OSError:
            print ("Creation of the directory %s failed" % mobileconfig_output_path)

    # setup lists and dictionaries
    profile_errors = []
    profile_types = {}
    
    # load the baseline.yaml file to process 
    profile_yaml = yaml.load(results.baseline, Loader=yaml.SafeLoader)
    
    # Read all rules in the section and output them
    for sections in profile_yaml['profile']:
        for profile_rule in sections['rules']:
            for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule_file=(os.path.basename(rule))
            
                #check for custom rule
                if rule_file in glob.glob1('../custom/rules/', '*.yaml'):
                    print(f"Custom settings found for rule: {rule_file}")
                    override_rule=os.path.join('../custom/rules', rule_file)
                    with open(override_rule) as r:
                        rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
                else:
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
        identifier = payload + f".{baseline_name}"
        description = "Configuration settings for the {} preference domain.".format(payload)
        
        newProfile = PayloadDict(identifier=identifier,
            uuid=False,
            removal_allowed=False,
            organization=organization,
            displayname=displayname,
            description=description)

        config_file = open(mobileconfig_file_path, "wb")

        if payload == "com.apple.ManagedClient.preferences":
            for item in settings:
                newProfile.addMCXPayload(item)
        elif (payload == "com.apple.applicationaccess.new") or (payload == 'com.apple.systempreferences'): #handle these payloads for array settings
            newProfile.addNewPayload(payload, concatenate_payload_settings(settings))
        else:
            newProfile.addNewPayload(payload, settings)

        newProfile.finalizeAndSave(config_file)
        config_file.close()

if __name__ == "__main__":
    main()
