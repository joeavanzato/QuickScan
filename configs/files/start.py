import yaml
import os
import sys
import logging
import datetime
import glob

import configuration_data
import helpers.hash_file
import helpers.write_detection

def launch():
    logging.info("Starting  'files' Config")
    print("STARTING FILE-NAME SCAN")
    name_data, ext_data, hash_list = read_configs()
    name_scan(name_data)
    extension_scan(ext_data, hash_list)


def read_configs():
    with open('configs\\files\\suspicious_names.yml') as f:
        try:
            name_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception("Error Reading configs\\files\\suspicious_names.yml")
            sys.exit(1)
    with open('configs\\files\\suspicious_extensions.yml') as f:
        try:
            extension_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception("Error Reading configs\\files\\suspicious_extensions.yml")
            sys.exit(1)
    with open('iocs\\primary_hashlist.txt') as f:
        hash_list = f.readlines()
    logging.info("Successfully Read: iocs\\primary_hashlist.txt")
    return name_data, extension_data, hash_list


def name_scan(name_data):
    detection_list = []
    logging.info("Starting File Name Scan")
    path_list = []
    matches = []
    paths = name_data['paths']
    names = name_data['names']
    for path in paths:
        expanded_path = os.path.expandvars(path)
        path_list.append(expanded_path)
    for path in path_list:
        for root, sub, f in os.walk(path):
            for file in f:
                if os.path.splitext(file)[0].lower() in names:
                    full_path = os.path.join(root, file)
                    print(f"Found Suspicious File Name: {full_path}")
                    matches.append(full_path)

    for match in matches:
        detection_base = {}
        detection_base['Name'] = "Suspicious File Name"
        detection_base['Reason'] = "A file with a known red-team/offensive or malicious name was detected."
        detection_base['File Path'] = str(match)
        detection_base['Registry Path'] = "NA"
        detection_base['MITRE Tactic'] = "Execution"
        detection_base['MITRE Technique'] = "NA"
        detection_base['Risk'] = "High"
        detection_base['Details'] = "NA"
        detection_list.append(detection_base)
    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)


def extension_scan(ext_data, hashes):
    logging.info("Starting File Extension Scan")
    path_list = []
    matches = []
    allow_list = []
    detection_list = []
    for path in ext_data['allowlist']:
        expanded_path = os.path.expandvars(path)
        allow_list.append(expanded_path)
        for root, sub, f in os.walk(expanded_path):
            allow_list.append(root)
        #expanded_paths = glob.glob(expanded_path, recursive=True)
        #for p in expanded_paths:
        #    if os.path.isdir(p):
        #        print(p)
        #        allow_list.append(p)
    for path in ext_data['paths']:
        expanded_path = os.path.expandvars(path)
        path_list.append(expanded_path)
    for path in path_list:
        for root, sub, f in os.walk(path):
            for file in f:
                if os.path.splitext(file)[1].lower() in ext_data['extensions'] and not root in allow_list:
                    #print(root)
                    #print(file)
                    full_path = os.path.join(root, file)
                    print(f"Found Suspicious File Extension: {full_path}")
                    md5, sha1, sha256 = helpers.hash_file.hash_file(full_path)
                    if md5 != "ERROR" and (md5 in hashes or sha1 in hashes or sha256 in hashes):
                        print(f"Found Suspicious File based on hash: {full_path}")
                        detection_base = {}
                        detection_base['Name'] = "File with Suspicious Hash"
                        detection_base['Reason'] = "A file with a known suspicious or malicious hash was detected."
                        detection_base['File Path'] = str(full_path)
                        detection_base['Registry Path'] = "NA"
                        detection_base['MITRE Tactic'] = "Execution"
                        detection_base['MITRE Technique'] = "NA"
                        detection_base['Risk'] = "High"
                        detection_base['Details'] = f"SHA256: {sha256}"
                        logging.info(f"Hash Match: {full_path}")
                        detection_list.append(detection_base)
                    else: #Don't alert twice on the same file
                        matches.append(full_path)

    for match in matches:
        detection_base = {}
        detection_base['Name'] = "Suspicious File Extension"
        detection_base['Reason'] = "A file with a suspicious extension was detected."
        detection_base['Registry Path'] = match
        detection_base['MITRE Tactic'] = "Execution"
        detection_base['MITRE Technique'] = "NA"
        detection_base['Risk'] = "Low"
        detection_base['Details'] = "NA"
        detection_list.append(detection_base)
    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)