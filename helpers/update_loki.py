import requests
import sys
import os

def launch():
    if not os.path.isdir('iocs'):
        try:
            os.mkdir('iocs')
        except PermissionError:
            print("PermissionError Creating Directory 'iocs'")
            sys.exit(1)
    try:
        hashlist = requests.get('https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt')
    except:
        print("Error Contacting GitHub!")
        sys.exit(1)
    with open('iocs/loki_hashlist.txt', 'w') as f:
        f.write(hashlist.text)
    with open('iocs/loki_hashlist.txt') as f:
        lines = f.readlines()
    with open('iocs/primary_hashlist.txt', 'a') as f:
        for line in lines:
            if not line.startswith("#") and line.strip() != "":
                try:
                    hash = line.split(";", 1)[0]
                except ValueError:
                    hash = line
                f.write(hash)