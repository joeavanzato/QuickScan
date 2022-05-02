import logging
import datetime
import os
import sys
import re

import yaml
import win32evtlog

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

# TODO - Parsing/Alerting Logic for 4624, 4648, Local Group Adds, etc.

def launch():
    logging.info("Starting  'evtx\\security' Config")
    print("STARTING evtx\\security SCAN")
    #command = 'powershell -Command "Get-WinEvent -FilterHashTable @{LogName=\'Security\'; Id=\'1100,1102,4624,4625,4648,4649,4688,4697,4698,4700,4702,4720,4722,4723,4724,4726,4732,5140\' }  | Select Id,RecordId,TimeCreated,Message | Export-Csv -NoTypeInformation -Path .\evidence\security.csv'
    command = 'powershell -Command "Get-WinEvent -FilterHashTable @{LogName=\'Security\'}  | Select Id,RecordId,TimeCreated,Message | Export-Csv -NoTypeInformation -Path .\evidence\security.csv'
    print("Exporting Security.evtx to CSV [This can take a few minutes if the log is large]..")
    result = helpers.execute.execute(command)
    #result = 0
    if not result == "ERROR":
        process("evidence\security.csv")

def process(file):
    data = helpers.csv_parse.parse(file)
    # Id	RecordId	TimeCreated	Message
    detection_list = []
    with open('configs\\evtx\\security\\malicious_commands.yml') as f:
        try:
            command_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception("Error Reading configs\\evtx\\security\\malicious_commands.yml")
            sys.exit(1)
    with open('configs\\evtx\\security\\malicious_commandline_regex.yml') as f:
        try:
            command_regex = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception("Error Reading configs\\evtx\\security\\malicious_commandline_regex.yml")
            sys.exit(1)

    re_list = []
    re_dict = {}
    for item in command_regex['keys']:
        re_item = command_regex['keys'][item]['command']
        re_list.append(re_item)
        re_dict[command_regex['keys'][item]['command']] = item #For reverse lookup in YAML

    command_dict = {}
    for item in command_data['keys']:
        #print(command_data['keys'][item]['command'])
        command_dict[command_data['keys'][item]['command']] = item #For reverse lookup in YAML


    for d in data:
        if d['Id'] == '4688':
            process_path, binary_name, command_line = parse_4688(d, command_dict, detection_list,command_regex, re_list, re_dict)
            if process_path != 0 :
                detection_base = {}
                print(f"Potentially Suspicious Binary Execution: {command_data['keys'][command_dict[binary_name]]['name']}")
                detection_base['Name'] = command_data['keys'][command_dict[binary_name]]['name']
                detection_base['Reason'] = command_data['keys'][command_dict[binary_name]]['description']
                if command_line != "":
                    detection_base['File Path'] = str(command_line)
                else:
                    detection_base['File Path'] = str(process_path)
                detection_base['Registry Path'] = "NA"
                detection_base['MITRE Tactic'] = command_data['keys'][command_dict[binary_name]]['tactic']
                detection_base['MITRE Technique'] = command_data['keys'][command_dict[binary_name]]['technique']
                detection_base['Risk'] = command_data['keys'][command_dict[binary_name]]['risk']
                detection_base['Details'] = str(d)
                detection_list.append(detection_base)
        if d['Id'] == '4624':
            remote_host, user, logon_type = parse_4624(d)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)

def parse_4624(row): #TODO
    ret = 0
    rows = row['Message'].split("\n")
    for row in rows:
        row = row.strip()
        if row.startswith('Logon Type'):
            print(row)


def parse_4688(row, command_dict, detection_list, command_regex, re_list, re_dict):
    ret = 0
    rows = row['Message'].split("\n")
    for row in rows:
        row = row.strip()
        if row.startswith("New Process Name"):
            process_name = row.split(":", 1)[1].strip()
            #print(process_name)
            binary_name = os.path.splitext(os.path.basename(process_name))[0]
            #print(binary_name)
            if binary_name in command_dict:
                ret = 1
        elif row.startswith("Process Command Line"):
            process_cl = row.split(":", 1)[1].strip()
            if process_cl != "" and ret == 0: #If we aren't already returning a detection and the command-line isn't blank AKA IS logging - should probably do GP check for appropriate policy instead.
                regex_4688(process_cl, detection_list,command_regex,  re_list, re_dict, row)
            #print(process_cl)
    if ret == 1:
        return process_name,binary_name, process_cl
    else:
        return 0,0,0

def regex_4688(commandline, detection_list,command_regex, re_list, re_dict, d):
    matches = {}
    for r in re_list:
        matches[r] = re.findall(r,commandline, re.IGNORECASE)

    for k,v in matches.items():
        if len(v) != 0:
            detection_base = {}
            print(f"Regex Detection for Suspicious Commandline: {command_regex['keys'][re_dict[k]]['name']}")
            detection_base['Name'] = command_regex['keys'][re_dict[k]]['name']
            detection_base['Reason'] = command_regex['keys'][re_dict[k]]['description']
            detection_base['File Path'] = str(commandline)
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = command_regex['keys'][re_dict[k]]['tactic']
            detection_base['MITRE Technique'] = command_regex['keys'][re_dict[k]]['technique']
            detection_base['Risk'] = command_regex['keys'][re_dict[k]]['risk']
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)

def read_eventlog(evt_log):
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    detection_list = []
    handle = win32evtlog.OpenEventLog(None, evt_log)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    event_count = win32evtlog.GetNumberOfEventLogRecords(handle)
    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if events:
            for event in events:
                if event.EventID == 4624:
                    print(f"Time Generated: {event.TimeGenerated}")
                    print(f"Event ID: {event.EventID}")
                    data = event.StringInserts
                    if data:
                        for d in data:
                            print(d)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




