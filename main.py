
# TODO - Add UAC Elevation / Admin Check


import os
import traceback
import sys
import argparse
import logging
import datetime
import csv

import configuration_data
import configs.files.start
import configs.services.start
import configs.tasks.start
import configs.false_extensions.start
import configs.network_connections.start
import configs.startup.start
import configs.prefetch.start
import configs.hash_scan.start
import configs.evtx.security.start
import configs.powershell.start
import helpers.update_loki



def parse_args():
    arguments = {}
    parser = argparse.ArgumentParser(usage='''
    ### QuickScan ###
    Rapidly Triage Windows Hosts for Suspicious Activity and Artifacts.
    

    Usage Examples:
    quickscan.exe 
    
    quickscan.exe -c prefetch,network_connections,services,startup
    
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
    if 'tasks' in args['configs']:
        configs.tasks.start.launch()
    if 'false_extensions' in args['configs']:
        configs.false_extensions.start.launch()
    if 'network_connections' in args['configs']:
        configs.network_connections.start.launch()
    if 'startup' in args['configs']:
        configs.startup.start.launch()
    if 'prefetch' in args['configs']:
        configs.prefetch.start.launch()
    if 'hash_scan' in args['configs']:
        configs.hash_scan.start.launch()
    if 'evtx' in args['configs']:
        configs.evtx.security.start.launch()
    if 'powershell' in args['configs']:
        configs.powershell.start.launch()


def start_detections(file, fields):
    with open(file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()


def build_hashset():
    if not os.path.isfile('iocs\\loki_hashlist.txt'):
        print("Updating Hash Set from Loki Signature Repository...")
        helpers.update_loki.launch()

def main():

    logo = '''
   ___       _    _    ___               
  / _ \ _  _(_)__| |__/ __| __ __ _ _ _  
 | (_) | || | / _| / /\__ \/ _/ _` | ' \ 
  \__\_\\_,_|_\__|_\_\|___/\__\__,_|_||_|                           
    '''
    logo2 = '''
░██████╗░██╗░░░██╗██╗░█████╗░██╗░░██╗░██████╗░█████╗░░█████╗░███╗░░██╗
██╔═══██╗██║░░░██║██║██╔══██╗██║░██╔╝██╔════╝██╔══██╗██╔══██╗████╗░██║
██║██╗██║██║░░░██║██║██║░░╚═╝█████═╝░╚█████╗░██║░░╚═╝███████║██╔██╗██║
╚██████╔╝██║░░░██║██║██║░░██╗██╔═██╗░░╚═══██╗██║░░██╗██╔══██║██║╚████║
░╚═██╔═╝░╚██████╔╝██║╚█████╔╝██║░╚██╗██████╔╝╚█████╔╝██║░░██║██║░╚███║
░░░╚═╝░░░░╚═════╝░╚═╝░╚════╝░╚═╝░░╚═╝╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝
'''
    print(logo2)
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
    build_hashset()
    launch_configs(args)


main()