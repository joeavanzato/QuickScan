import yaml
import os
import sys
import logging
import datetime

import configuration_data
import helpers.hash_file

def launch():
    logging.info("Starting  'hash_scan' Config")
    print("STARTING HASH SCAN")
    hash_list, ext_data = read_configs()
    extension_scan(hash_list, ext_data)


def read_configs():
    with open('configs\\hash_scan\\suspicious_extensions_extended.yml') as f:
        try:
            extension_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception("Error Reading configs\\hash_scan\\suspicious_extensions_extended.yml")
            sys.exit(1)
    logging.info("Successfully Read: configs\\hash_scan\\suspicious_extensions_extended.yml")
    with open('iocs\\primary_hashlist.txt') as f:
        hash_list = f.readlines()
    logging.info("Successfully Read: iocs\\primary_hashlist.txt")
    return  hash_list, extension_data

def extension_scan(hashes, ext_data):
    logging.info("Starting File Extension Scan")
    path_list = []
    allow_list = []
    detection_list = []
    for path in ext_data['allowlist']:
        expanded_path = os.path.expandvars(path)
        allow_list.append(expanded_path)
        #print(expanded_path)
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
            logging.info(f"Scanning: {root}")
            for file in f:
                if os.path.splitext(file)[1].lower() in ext_data['extensions'] and not root in allow_list:
                    full_path = os.path.join(root, file)
                    md5, sha1, sha256 = helpers.hash_file.hash_file(full_path)
                    if md5 != "ERROR" and (md5 in hashes or sha1 in hashes or sha256 in hashes):
                        print(f"Found Suspicious File based on hash: {full_path}")
                        detection_base = {}
                        detection_base['Name'] = "File with Suspicious Hash"
                        detection_base['Reason'] = "QuickScan detected a file having a known suspicious hash."
                        detection_base['File Path'] = str(full_path)
                        detection_base['Registry Path'] = "NA"
                        detection_base['MITRE Tactic'] = "Execution"
                        detection_base['MITRE Technique'] = "NA"
                        detection_base['Risk'] = "High"
                        detection_base['Details'] = f"SHA256: {sha256}"
                        logging.info(f" Hash Match: {full_path}")
                        detection_list.append(detection_base)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)