import yaml
import os
import sys
import logging
import datetime
import glob

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'files' Config")
    print("STARTING FILE-NAME SCAN")
    name_data, ext_data = read_configs()
    #file_list = name_scan(name_data)
    ext_list = extension_scan(ext_data)


def read_configs():
    with open('configs\\files\\suspicious_names.yml') as f:
        try:
            name_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception(str(datetime.datetime.now()) + " Error Reading configs\\files\\suspicious_names.yml")
            sys.exit(1)
    with open('configs\\files\\suspicious_extensions.yml') as f:
        try:
            extension_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception(str(datetime.datetime.now()) + " Error Reading configs\\files\\suspicious_extensions.yml")
            sys.exit(1)
    return name_data, extension_data


def name_scan(name_data):
    logging.info(str(datetime.datetime.now()) + " Starting File Name Scan")
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
    return path_list


def extension_scan(ext_data):
    logging.info(str(datetime.datetime.now()) + " Starting File Extension Scan")
    path_list = []
    matches = []
    allow_list = []
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
            for file in f:
                if os.path.splitext(file)[1].lower() in ext_data['extensions'] and not root in allow_list:
                    #print(root)
                    #print(file)
                    full_path = os.path.join(root, file)
                    print(f"Found Suspicious File Extension: {full_path}")
                    matches.append(full_path)
    return path_list