# get-nettcpconnection | select local*,remote*,state,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -NoTypeInformation -Path .\test5.csv

import logging
import datetime
import os

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

# Field Output
# LocalAddress	LocalPort	RemoteAddress	RemotePort	State	Process

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'network_connections' Config")
    print("STARTING NETWORK CONNECTION SCAN")
    command = 'powershell -Command  "Get-NetTcpConnection | Select-Object local*,remote*,state,@{Name=\'Process\';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -NoTypeInformation -Path .\evidence\connections.csv"'
    result = helpers.execute.execute(command)
    if not result == "ERROR":
        process_services("evidence\connections.csv")

def process_services(file):
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    data = helpers.csv_parse.parse(file)
    detection_list = []
    for d in data:
        local_ip = d['LocalAddress']
        local_port = d['LocalPort']
        remote_ip = d['RemoteAddress']
        remote_port = d['RemotePort']
        state = d['State']
        process_name = d['Process']
        if state == "Listen" and remote_port == ["3389"] and process_name == 'svchost':
            print(f"RDP Listening for Connections")
            detection_base = {}
            detection_base['Name'] = "RDP Listening for Connections"
            detection_base['Reason'] = "Malware and Threat Actors often use RDP as a persistence mechanism - ensure that listening for connections is normal."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Low"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)
        if state.startswith("Established") and (remote_port == ["3389"] or process_name == 'mstsc'):
            print(f"Outbound RDP Connection to: {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Outbound RDP Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use RDP as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "High"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)
        if state.startswith("Established") and local_port == ["3389"]:
            print(f"Inbound RDP Connection from: {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Inbound RDP Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use RDP as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "High"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)
        if state.startswith("Established") and remote_port in ["5985", "5986"] and process_name == 'powershell':
            print(f"Outbound WinRM Connection to: {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Outbound WinRM Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use WinRM as a lateral movement mechanism - ensure that the outbound connection is not malicious."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)
        if state.startswith("Established") and local_port in ["5985", "5986"]:
            print(f"Potential Inbound WinRM Connection to: {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Potential Inbound WinRM Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use WinRM as a lateral movement mechanism - ensure that the outbound connection is not malicious."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)
        if state == "Listen" and local_port in ["5985", "5986"]:
            print(f"Listening for WinRM Connections")
            detection_base = {}
            detection_base['Name'] = "WinRM Connection Listener"
            detection_base['Reason'] = "Malware and Threat Actors often use WinRM as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




