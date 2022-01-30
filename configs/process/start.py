import logging
import datetime
import os
import sys
import re

import yaml

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

# Field Output

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'process' Config")
    print("STARTING PROCESS SCAN")
    command = 'powershell -Command  Get-CimInstance Win32_Process | Select-Object * | Export-CSV -NoTypeInformation -Path .\evidence\\processes.csv"'
    result = helpers.execute.execute(command)

    with open('configs\\evtx\\security\\malicious_commandline_regex.yml') as f:
        try:
            command_regex = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception(str(datetime.datetime.now()) + " Error Reading configs\\evtx\\security\\malicious_commandline_regex.yml")
            sys.exit(1)

    with open('configs\\files\\suspicious_names.yml') as f:
        try:
            name_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception(str(datetime.datetime.now()) + " Error Reading configs\\files\\suspicious_names.yml")
            sys.exit(1)

    re_list = []
    re_dict = {}
    for item in command_regex['keys']:
        re_item = command_regex['keys'][item]['command']
        #print(re_item)
        re_list.append(re_item)
        re_dict[command_regex['keys'][item]['command']] = item #For reverse lookup in YAML

    if not result == "ERROR":
        process("evidence\processes.csv", re_list, command_regex, name_data, re_dict)

def process(file, re_list, command_regex, name_data, re_dict):
    detection_list = []
    data = helpers.csv_parse.parse(file)
    for d in data:
        name = d['ProcessName']
        command_line = d['CommandLine']
        path = d['Path']
        matches = {}
        for r in re_list:
            matches[r] = re.findall(r, command_line, flags=re.IGNORECASE | re.MULTILINE)
        for k, v in matches.items():
            if len(v) != 0:
                detection_base = {}
                print(f"Regex Detection on Active Process {command_regex['keys'][re_dict[k]]['name']}")
                detection_base['Name'] = command_regex['keys'][re_dict[k]]['name']
                detection_base['Reason'] = command_regex['keys'][re_dict[k]]['description']
                detection_base['File Path'] = "NA"
                detection_base['Registry Path'] = "NA"
                detection_base['MITRE Tactic'] = command_regex['keys'][re_dict[k]]['tactic']
                detection_base['MITRE Technique'] = command_regex['keys'][re_dict[k]]['technique']
                detection_base['Risk'] = command_regex['keys'][re_dict[k]]['risk']
                detection_base['Details'] = str(d)
                detection_list.append(detection_base)

        #TODO - Hash File at Path for Known Matches
        #TODO - Known Suspicious Name Match

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




