import os
import traceback
import csv
import json
import yaml
import sys
import argparse
import logging
import datetime
import csv

import configuration_data
import configs.files.start
import configs.services.start

def parse_args():
    arguments = {}
    parser = argparse.ArgumentParser(usage='''
    ### QuickScan ###
    Rapidly Triage Windows Hosts for Suspicious Activity and Artifacts.

    Usage Examples:
    quickscan.exe 
    
    quickscan.exe -c 
    ''')
    parser.add_argument("-c", "--configs", help="Which Configurations to Run - if left blank, will run all.",
                        required=False, nargs=1, type=str)
    args = parser.parse_args()

    available_configs = os.listdir('configs')

    if args.configs:
        try:
            config_list = args.configs[0].split(',')
        except:
            configs = args.configs[0]
            config_list[0] = configs
        for c in config_list:
            if c not in available_configs:
                print(f"Error: Could not find config - {c}")
                sys.exit(1)
            else:
                pass
        arguments['configs'] = config_list
    else:
        arguments['configs'] = available_configs
    print(f"Using Configs: {arguments['configs']}")

    return arguments


def launch_configs(args):
    if 'files' in args['configs']:
        configs.files.start.launch()
    if 'services' in args['configs']:
        configs.services.start.launch()

def start_detections(file, fields):
    with open(file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()


def main():
    print("### QuickScan ###")
    print("https://github.com/joeavanzato/QuickScan")
    args = parse_args()
    log_file = "quickscan_log.log"
    logging.basicConfig(filename=log_file, level=logging.DEBUG)
    logging.info(str(datetime.datetime.now()) + " New Logger Initialized")
    try:
        os.mkdir('evidence')
    except OSError as e:
        pass
    configuration_data.fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    configuration_data.detection_csv = 'detection_output.csv'
    start_detections(configuration_data.detection_csv, configuration_data.fields)
    launch_configs(args)


main()