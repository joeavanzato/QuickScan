import logging
import datetime
import os
import sys
import glob
import re

import yaml

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

# TODO - Maybe handle start-transcript files in C:\Users\*\Documents

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'powershell' Config")
    print("STARTING POWERSHELL HISTORY SCAN")
    path = f'''{os.getenv("HOMEDRIVE")}\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'''
    paths = glob.glob(path)
    try:
        for f in paths:
            process(f)
    except PermissionError:
        print(f"PermissionError: Couldn't Read {os.getenv('SYSTEMROOT')}\\Prefetch")



def process(file):
    with open('configs\\evtx\\security\\malicious_commandline_regex.yml') as f:
        try:
            regex_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception(str(datetime.datetime.now()) + " Error Reading configs\\files\\suspicious_names.yml")
            sys.exit(1)
    re_list = []
    re_dict = {}
    for item in regex_data['keys']:
        re_item = regex_data['keys'][item]['command']
        re_list.append(re_item)
        re_dict[regex_data['keys'][item]['command']] = item #For reverse lookup in YAML

    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    detection_list = []
    with open(file, 'r') as f:
        for line in f:
            line = line.strip()
            regex_check(line, detection_list, regex_data, re_list, re_dict)


    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)

def regex_check(line, detection_list, regex_data, re_list, re_dict):
    matches = {}
    for r in re_list:
        matches[r] = re.findall(r,line, re.IGNORECASE)

    for k,v in matches.items():
        if len(v) != 0:
            detection_base = {}
            print(f"Regex Detection in PowerShell History File: {regex_data['keys'][re_dict[k]]['name']}: {line}")
            detection_base['Name'] = regex_data['keys'][re_dict[k]]['name']
            detection_base['Reason'] = regex_data['keys'][re_dict[k]]['description']
            detection_base['File Path'] = str(regex_data)
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = regex_data['keys'][re_dict[k]]['tactic']
            detection_base['MITRE Technique'] = regex_data['keys'][re_dict[k]]['technique']
            detection_base['Risk'] = regex_data['keys'][re_dict[k]]['risk']
            detection_base['Details'] = str(line)
            detection_list.append(detection_base)




