
import subprocess
import traceback
import logging
import datetime

def execute(command):
    try:
        print(command)
        logging.info(str(datetime.datetime.now()) + " Executing: "+command)
        result = subprocess.run(args=command, capture_output=True, check=True)
        return result.stdout.decode('utf-8', errors='replace')
    except:
        print(traceback.print_exc(limit=None, file=None, chain=True))
        return 'ERROR'