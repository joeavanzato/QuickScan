import logging
import datetime
import os

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

# Field Output
# Caption	Description	Command	Location	Name	User	UserSID	PSComputerName

def launch():
    logging.info("Starting  'startup' Config")
    print("STARTING STARTUP SCAN")
    print(os.getcwd())
    command = 'powershell Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Caption,Description,Command,Location,Name,User,UserSID,PSComputerName | Export-CSV -NoTypeInformation -Path ".\evidence\startup.csv"'
    result = helpers.execute.execute(command)
    if not result == "ERROR":
        process_services("evidence\startup.csv")

def process_services(file):
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    data = helpers.csv_parse.parse(file)
    detection_list = []
    for d in data:
        caption = d['Caption']
        description = d['Description']
        command = d['Command']
        location = d['Location']
        name = d['Name']
        user = d['User']
        user_sid = d['UserSID']
        computer_name = d['PSComputerName']
        command_replace = command.replace("\"", "")
        if len(caption) < 4:
            print(f"Abnormally Short Startup Name: {caption},{command}")
            detection_base = {}
            detection_base['Name'] = "Abnormally Short Service Name"
            detection_base['Reason'] = "Malware and Threat Actors often use short/randomized names for startup items."
            detection_base['File Path'] = command
            detection_base['Registry Path'] = location
            detection_base['MITRE Tactic'] = "Execution, Persistence, Privilege Escalation"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Low"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)
        if command_replace.startswith("C:\\Users"):
            print(f"Startup Item from Users Directory: {caption},{command}")
            detection_base = {}
            detection_base['Name'] = "Startup Binary in Users Directory"
            detection_base['Reason'] = "Malware and Threat Actors often use binaries from within C:\\Users."
            detection_base['File Path'] = command
            detection_base['Registry Path'] = location
            detection_base['MITRE Tactic'] = "Execution, Persistence, Privilege Escalation"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)


    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




