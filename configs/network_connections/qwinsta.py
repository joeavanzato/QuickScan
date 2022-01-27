import logging
import datetime
import os

import configuration_data
import configs.network_connections.qwinsta
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'startup' Config")
    print("STARTING STARTUP SCAN")
    print(os.getcwd())
    command = 'qwinsta'
    result = helpers.execute.execute(command)
    if not result == "ERROR":
        process_result(result)


def process_result(result):
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    results = result.split("\n")


    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)
