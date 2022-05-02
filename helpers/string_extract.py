
import os
import string
import sys
import re
import yaml
import logging
import datetime

def launch(minimum_length, file, pattern):
    if os.path.getsize(file) < 104857600:
        with open(file, errors='ignore') as f:
            result = ""
            for char in f.read():
                if char in string.printable:
                    result += char
                    continue
                if len(result) >= minimum_length:
                    yield result
                result = ""
            if len(result) >= minimum_length:
                yield result
    else:
        print(os.path.getsize(file) )

minimum_length = 10
chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
reg = f'[{chars}]{{{minimum_length},}}'
pattern = re.compile(reg)
with open('helpers\\suspicious_strings.yml') as f:
    try:
        string_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(e)
        logging.exception(
            str(datetime.datetime.now()) + " Error Reading configs\\hash_scan\\suspicious_extensions_extended.yml")
        sys.exit(1)
mal_strings = string_data['strings']
for s in launch(10, r'C:\Users\Joe\Downloads\mimikatz_trunk\x64\mimikatz.exe', pattern):
    if s in mal_strings:
        print(s)