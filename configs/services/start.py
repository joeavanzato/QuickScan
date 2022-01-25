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

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'services' Config")
    print("STARTING SERVICE SCAN")
    print(os.getcwd())
    command = 'powershell Get-WmiObject win32_service | Select * | Export-Csv -NoTypeInformation -Path ".\evidence\services.csv"'
    result = helpers.execute.execute(command)
    if not result == "ERROR":
        process_services("evidence\services.csv")

def process_services(file):
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    data = helpers.csv_parse.parse(file)
    detection_list = []
    for d in data:
        image_path = d['PathName']
        image_path = image_path.replace("\"", "")
        base_image = os.path.split(image_path)
        if os.path.isdir(base_image[0]):
            file_image = base_image[1]
        else:
            file_image = base_image[0]
        try:
            base_file = file_image.split(" ", 1)[0]
        except ValueError:
            base_file = file_image
        try:
            base_file = base_file.rsplit('.', 1)[0]
        except:
            pass
        if len(base_file) < 4:
            print(f"Abnormally Short Image Path: {image_path}")
            detection_base = {}
            detection_base['Name'] = "Abnormally short service name"
            detection_base['Reason'] = "Malware and Threat Actors often use short/randomized executables"
            detection_base['File Path'] = image_path
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Execution, Persistence, Privilege Escalation"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




