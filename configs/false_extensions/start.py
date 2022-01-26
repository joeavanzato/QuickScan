import yaml
import os
import sys
import logging
import datetime
import glob

import configuration_data
import helpers.write_detection

#detection_base = {}
#detection_base['Name'] = "Abnormally Short Service Name"
#detection_base['Reason'] = "Malware and Threat Actors often use short/randomized executables"
#detection_base['File Path'] = image_path
#detection_base['Registry Path'] = "NA"
#detection_base['MITRE Tactic'] = "Execution, Persistence, Privilege Escalation"
#detection_base['MITRE Technique'] = "NA"
#detection_base['Risk'] = "Medium"
#detection_base['Details'] = str(d)

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'files' Config")
    print("STARTING TRAILING-SPACE SCAN")
    extension_scan()


def extension_scan():
    logging.info(str(datetime.datetime.now()) + " Starting File Extension Scan")
    path_list = []
    matches = []
    detection_list = []
    allow_list = []
    #for path in ext_data['allowlist']:
    #    expanded_path = os.path.expandvars(path)
    #    allow_list.append(expanded_path)
    #    #print(expanded_path)
    #    for root, sub, f in os.walk(expanded_path):
    #        allow_list.append(root)
        #expanded_paths = glob.glob(expanded_path, recursive=True)
        #for p in expanded_paths:
        #    if os.path.isdir(p):
        #        print(p)
        #        allow_list.append(p)
    homedir = os.getenv("HOMEDRIVE")
    for root, sub, f in os.walk(homedir+"\\"):
        for file in f:
            name, extension = os.path.splitext(file)
            extension = extension.replace(".", "").lower()
            if extension in configuration_data.bad_extensions and extension.endswith(" "):# in ext_data['extensions'] and not root in allow_list:
                detection_base = {}
                full_path = os.path.join(root, file)
                print(f"Found Suspicious File Extension with Trailing Space: {full_path}")
                detection_base['Name'] = "Extension with Trailing Space"
                detection_base['Reason'] = "Malware and Threat Actors often use false extensions to disguise the true OS-interpreted extension used at runtime."
                detection_base['File Path'] = full_path
                detection_base['Registry Path'] = "NA"
                detection_base['MITRE Tactic'] = "Execution"
                detection_base['MITRE Technique'] = "T1036.006"
                detection_base['Risk'] = "High"
                detection_base['Details'] = "NA"
                detection_list.append(detection_base)
                matches.append(full_path)
    logging.info(str(datetime.datetime.now()) + " False Extension Scan Complete")
    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)
    return path_list