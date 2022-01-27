import logging
import datetime
import os
import sys
import yaml

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

# Field Output

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'prefetch' Config")
    print("STARTING PREFETCH SCAN")
    try:
        contents = os.listdir(os.getenv("SYSTEMROOT")+"\\Prefetch")
        process(contents)
    except PermissionError:
        print(f"PermissionError: Couldn't Read {os.getenv('SYSTEMROOT')}\\Prefetch")



def process(contents):
    with open('configs\\files\\suspicious_names.yml') as f:
        try:
            name_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(e)
            logging.exception(str(datetime.datetime.now()) + " Error Reading configs\\files\\suspicious_names.yml")
            sys.exit(1)
    suspicious_names = name_data['names']
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    detection_list = []
    for f in contents:

        try:
            binary = f.split(".", 1)[0]
        except ValueError:
            binary = f
        if binary.lower() in suspicious_names:
            #stats = os.stat(os.getenv('SYSTEMROOT') + '\\Prefetch\\' + f)
            #mtime = stats.st_mtime
            #atime = stats.st_atime
            #ctime = stats.st_ctime
            print(f"Suspicious Binary Name in Prefetch: {binary}")
            detection_base = {}
            detection_base['Name'] = "Suspicious Binary in Prefetch"
            detection_base['Reason'] = "The Prefetch stores historical data on binary execution."
            detection_base['File Path'] = "Parse Relevant Prefetch File to Retrieve this"
            detection_base['Registry Path'] = "NA"
            detection_base['MITRE Tactic'] = "Execution"
            detection_base['MITRE Technique'] = "NA"
            detection_base['Risk'] = "High"
            detection_base['Details'] = str(os.getenv('SYSTEMROOT') + '\\Prefetch\\' + f)
            detection_list.append(detection_base)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




