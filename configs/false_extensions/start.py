import yaml
import os
import sys
import logging
import datetime
import glob

import configuration_data


def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'files' Config")
    print("STARTING TRAILING-SPACE SCAN")
    extension_scan()


def extension_scan():
    logging.info(str(datetime.datetime.now()) + " Starting File Extension Scan")
    path_list = []
    matches = []
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
            if os.path.splitext(file)[1].lower() in configuration_data.bad_extensions and os.path.splitext(file)[1].lower().endswith(" "):# in ext_data['extensions'] and not root in allow_list:
                full_path = os.path.join(root, file)
                print(f"Found Suspicious File Extension with Trailing Space: {full_path}")
                matches.append(full_path)
    return path_list