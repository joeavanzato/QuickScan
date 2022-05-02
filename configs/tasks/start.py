import logging
import datetime
import os

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

# Field Output
# PSComputerName	Name	Status	ExitCode	DesktopInteract	ErrorControl	PathName	ServiceType	StartMode
# __GENUS	__CLASS	__SUPERCLASS	__DYNASTY	__RELPATH	__PROPERTY_COUNT	__DERIVATION	__SERVER	__NAMESPACE
# __PATH	AcceptPause	AcceptStop	Caption	CheckPoint	CreationClassName	DelayedAutoStart	Description	DisplayName
# InstallDate	ProcessId	ServiceSpecificExitCode	Started	StartName	State	SystemCreationClassName	SystemName	TagId
# WaitHint	Scope	Path	Options	ClassPath	Properties	SystemProperties	Qualifiers	Site	Container

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
    logging.info("Starting  'tasks' Config")
    print("STARTING SCHEDULED TASK SCAN")
    print(os.getcwd())
    command = 'powershell schtasks /query /v /fo csv | ConvertFrom-CSV | Export-CSV -NoTypeInformation -Path ".\\evidence\\tasks.csv"'
    result = helpers.execute.execute(command)
    if not result == "ERROR":
        process_services("evidence\\tasks.csv")

def process_services(file):
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    data = helpers.csv_parse.parse(file)
    detection_list = []
    for d in data:
        if not d['HostName'] == 'HostName': #Sometimes we are seeing the headers row repeat multiple times - not sure why.
            task_name = d['TaskName']
            task_to_run = d['Task To Run']
            try:
                base_task, arguments = task_to_run.split(" ", 1)
            except ValueError:
                base_task = task_to_run
            try:
                file, extension = base_task.rsplit('.', 1)
            except ValueError:
                file = base_task
                extension = "NA"


            if len(task_name) < 5:
                detection_base = {}
                print(f'Abnormally Short Task Name: {task_name}')
                detection_base['Name'] = "Abnormally Short Task Name"
                detection_base['Reason'] = "Malware and Threat Actors often use short/randomized naming conventions"
                detection_base['File Path'] = task_to_run
                detection_base['Registry Path'] = "NA"
                detection_base['MITRE Tactic'] = "Execution, Persistence, Privilege Escalation"
                detection_base['MITRE Technique'] = "NA"
                detection_base['Risk'] = "Medium"
                detection_base['Details'] = str(d)
                detection_list.append(detection_base)
            if extension.strip().lower() in configuration_data.bad_extensions:
                detection_base = {}
                print(f'Potentially Dangerous Scheduled Task Extension: {task_to_run}')
                detection_base['Name'] = "Potentially Dangerous Scheduled Task Extension"
                detection_base['Reason'] = "Malware and Threat Actors often use common extensions that allow dangerous capabilities"
                detection_base['File Path'] = task_to_run
                detection_base['Registry Path'] = "NA"
                detection_base['MITRE Tactic'] = "Execution, Persistence, Privilege Escalation"
                detection_base['MITRE Technique'] = "NA"
                detection_base['Risk'] = "Medium"
                detection_base['Details'] = str(d)
                detection_list.append(detection_base)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




