import logging
import datetime
import os
import win32evtlog

import configuration_data
import helpers.execute
import helpers.csv_parse
import helpers.write_detection

def launch():
    logging.info(str(datetime.datetime.now()) + " Starting  'evtx\\security' Config")
    print("STARTING evtx\\security SCAN")
    process("Security")

def process(evt_log):
    #fields = ['Name', 'Reason','File Path','Registry Path','MITRE Tactic','MITRE Technique','Risk','Details']
    detection_list = []
    handle = win32evtlog.OpenEventLog(None, evt_log)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    event_count = win32evtlog.GetNumberOfEventLogRecords(handle)
    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if events:
            for event in events:
                print(f"Time Generated: {event.TimeGenerated}")
                print(f"Event ID: {event.EventID}")
                data = event.StringInserts
                if data:
                    for d in data:
                        print(d)

    helpers.write_detection.write_detection(configuration_data.detection_csv, configuration_data.fields, detection_list)




