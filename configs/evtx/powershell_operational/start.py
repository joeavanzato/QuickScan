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

# TODO - Parsing/Alerting Logic for 4624, 4648, Local Group Adds, etc.

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'evtx\\powershell_operational' Config")
    print("STARTING POWERSHELL OPERATIONAL SCAN")
    #command = 'powershell -Command "Get-WinEvent -FilterHashTable @{LogName=\'Security\'; Id=\'1100,1102,4624,4625,4648,4649,4688,4697,4698,4700,4702,4720,4722,4723,4724,4726,4732,5140\' }  | Select Id,RecordId,TimeCreated,Message | Export-Csv -NoTypeInformation -Path .\evidence\security.csv'
    command = 'powershell -Command "Get-WinEvent -FilterHashTable @{LogName=\'Microsoft-Windows-PowerShell/Operational\'}  | Select Id,RecordId,TimeCreated,Message | Export-Csv -NoTypeInformation -Path .\evidence\\powershell_operational.csv'
    print("Exporting Microsoft-Windows-PowerShell-Operational.evtx to CSV [This can take a few minutes if the log is large]..")
    result = helpers.execute.execute(command)
    #result = 0
    if not result == "ERROR":
        process("evidence\\powershell_operational.csv")
    else:
        print("ERROR Executing Command")

def process(file):
    data = helpers.csv_parse.parse(file)
    # Id	RecordId	TimeCreated	Message
    detection_list = []
    with open('configs\\evtx\\security\\malicious_commands.yml') as f:
        try:
            command_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception(str(datetime.datetime.now()) + " Error Reading configs\\evtx\\security\\malicious_commands.yml")
            sys.exit(1)
    with open('configs\\evtx\\security\\malicious_commandline_regex.yml') as f:
        try:
            command_regex = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception(str(datetime.datetime.now()) + " Error Reading configs\\evtx\\security\\malicious_commandline_regex.yml")
            sys.exit(1)
    try:
        with open('iocs\\primary_ip_list.txt', 'r') as f:
            mal_ips = f.readlines()
    except:
        mal_ips = []
    ip_pattern = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
    ip_compiled = re.compile(ip_pattern)

    re_list = []
    re_dict = {}
    for item in command_regex['keys']:
        re_item = command_regex['keys'][item]['command']
        #print(re_item)
        re_list.append(re_item)
        re_dict[command_regex['keys'][item]['command']] = item #For reverse lookup in YAML

    for d in data:
        if d['Id'] in ['4104', '4103']:
            parse(d, detection_list,command_regex, re_list, re_dict, mal_ips, ip_compiled)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)



def parse(row, detection_list, command_regex, re_list, re_dict, mal_ips, ip_compiled):
    matches = {}
    for r in re_list:
        matches[r] = re.findall(r,row['Message'], flags=re.IGNORECASE | re.MULTILINE)
    for k,v in matches.items():
        if len(v) != 0:
            detection_base = {}
            print(f"Regex Detection for Suspicious PowerShell {command_regex['keys'][re_dict[k]]['name']}")
            detection_base['Name'] = command_regex['keys'][re_dict[k]]['name']
            detection_base['Reason'] = command_regex['keys'][re_dict[k]]['description']
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = command_regex['keys'][re_dict[k]]['tactic']
            detection_base['MITRE Technique'] = command_regex['keys'][re_dict[k]]['technique']
            detection_base['Risk'] = command_regex['keys'][re_dict[k]]['risk']
            detection_base['Details'] = str(row)
            detection_list.append(detection_base)

    matches = ip_compiled.findall(row['Message'])
    for match in matches:
        if match in mal_ips:
            print(f"Suspicious IP Found in PowerShell Logs: {match}")
            detection_base['Name'] = "Suspicious IP Found in PowerShell Logs"
            detection_base['Reason'] = "A known suspicious/malicious IP Address was found in Operational PowerShell Logging."
            detection_base['File Path'] = f"{match}"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Command and Control"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "High"
            detection_base['Details'] = str(row)
            detection_list.append(detection_base)






