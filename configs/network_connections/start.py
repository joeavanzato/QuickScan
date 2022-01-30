# get-nettcpconnection | select local*,remote*,state,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -NoTypeInformation -Path .\test5.csv

import logging
import datetime
import os

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection
import configs.network_connections.qwinsta
# Field Output
# LocalAddress	LocalPort	RemoteAddress	RemotePort	State	Process

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'network_connections' Config")
    print("STARTING NETWORK CONNECTION SCAN")
    command = 'powershell -Command  "Get-NetTcpConnection | Select-Object local*,remote*,state,@{Name=\'Process\';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-CSV -NoTypeInformation -Path .\evidence\connections.csv"'
    result = helpers.execute.execute(command)
    if not result == "ERROR":
        process_services("evidence\connections.csv")
    #configs.network_connections.qwinsta.launch()

def process_services(file):
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    data = helpers.csv_parse.parse(file)
    try:
        with open('iocs\\primary_ip_list.txt', 'r') as f:
            mal_ips = f.readlines()
    except:
        mal_ips = []
    detection_list = []
    for d in data:
        local_ip = d['LocalAddress']
        local_port = d['LocalPort']
        remote_ip = d['RemoteAddress']
        remote_port = d['RemotePort']
        state = d['State']
        process_name = d['Process']
        if remote_ip in mal_ips:
            print(f"Connection to Suspicious IP Address: {local_ip}:{local_port} <-> {remote_ip}:{remote_port}")
            detection_base = {}
            detection_base['Name'] = "Connection to Suspicious IP Address"
            detection_base['Reason'] = "A connection to a known suspicious or malicious IP address was detected."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Command and Control"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "High"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
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
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
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
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
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
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
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
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state.startswith("Established") and local_port in ["5985", "5986"]:
            print(f"Potential Inbound WinRM Connection to: {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Potential Inbound WinRM Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use WinRM as a lateral movement mechanism - ensure that the inbound connection is not malicious."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
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
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state == "Listen" and local_port == "22":
            print(f"Listening for SSH Connections")
            detection_base = {}
            detection_base['Name'] = "SSH Connection Listener"
            detection_base['Reason'] = "Malware and Threat Actors often use SSH as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state.startswith("Established") and local_port == "22":
            print(f"Inbound SSH Connection from {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Inbound SSH Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use SSH as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "High"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state.startswith("Established") and remote_port == "22":
            print(f"Outbound SSH Connection to {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Outbound SSH Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use SSH as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state == "Listen" and local_port == "23":
            print(f"Listening for TelNet Connections")
            detection_base = {}
            detection_base['Name'] = "TelNet Connection Listener"
            detection_base['Reason'] = "Malware and Threat Actors often use TelNet as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            detection_list.append(detection_base)
        if state.startswith("Established") and (local_port == "23" or remote_port == "23"):
            print(f"Established TelNet Connection to/from {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "TelNet Connection Established"
            detection_base['Reason'] = "Malware and Threat Actors often use TelNet as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state == "Listen" and local_port == "445":
            print(f"Listening for SMB Connections")
            detection_base = {}
            detection_base['Name'] = "SMB Connection Listener"
            detection_base['Reason'] = "Malware and Threat Actors often use SMB as an initial access or lateral movement mechanism."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state.startswith("Established") and remote_port in ["139, 445"]:
            print(f"Potential Outbound SMB Connection to: {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Potential Outbound SMB Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use SMB as a lateral movement mechanism - ensure that the outbound connection is not malicious."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state.startswith("Established") and local_port in ["139, 445"]:
            print(f"Potential Inbound SMB Connection from: {remote_ip}")
            detection_base = {}
            detection_base['Name'] = "Potential Inbound SMB Connection"
            detection_base['Reason'] = "Malware and Threat Actors often use SMB as a lateral movement mechanism - ensure that the inbound connection is not malicious."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "Medium"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state.startswith("Established") and process_name.lower() in ["svchost", "lsass","smss","csrss","wininit","services","lsm","winlogon","explorer"]:
            print(f"System Process with Established Connection: {process_name}:{remote_ip}")
            detection_base = {}
            detection_base['Name'] = "System Process with Established Connection"
            detection_base['Reason'] = "Malware and Threat Actors often abuse system processes or malicious threads with identical names to avoid detection."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "High"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)
        if state.startswith("Established") and (local_port in ["5900"] or remote_port in ["5900"]):
            print(f"Potential VNC Connection: {process_name}:{local_port} to {remote_ip}:{remote_port}")
            detection_base = {}
            detection_base['Name'] = "Potential VNC Connection"
            detection_base['Reason'] = "Malware and Threat Actors often abuse VNC protocols for C2."
            detection_base['File Path'] = "NA"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Initial Access, Lateral Movement"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "High"
            detection_base['Details'] = str(d)
            logging.info(str(datetime.datetime.now()) + f" New Detection: {detection_base['Name']}")
            detection_list.append(detection_base)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




