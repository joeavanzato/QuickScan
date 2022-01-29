import requests
import sys
import os
import re


def launch(url_list):
    """
    Receive dictionary containing file_name reference and URL as k,v pair - pass each K,V to update_list function if a file
    reference doesn't already exist.
    :param url_list:
    :return:
    """
    if not os.path.isdir('iocs'):
        try:
            os.mkdir('iocs')
        except PermissionError:
            print("PermissionError Creating Directory 'iocs'")
            sys.exit(1)
    #ip_pattern = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ip_pattern = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
    ip_compiled = re.compile(ip_pattern)

    for name, url in url_list.items():
        if not os.path.isfile("iocs/"+name+"_ips.txt"):
            update_list(url, name, ip_compiled)
        else:
            print(f'Skipping IP Update for {url}')

def update_list(url, filename, ip_compiled):
    """
    Receive a URL, Filename and basic compiled regex for IP addresses - download the relevant data and push it to the primary IOC file for IPs.
    :param url:
    :param filename:
    :param ip_compiled:
    :return:
    """
    try:
        list = requests.get(url)
    except:
        print(f"Error Contacting {url}")
        return
    with open(f'iocs/{filename}_ips.txt', 'w') as f:
        f.write(list.text)
    with open('iocs/primary_ip_list.txt', 'a') as dest:
        with open(f'iocs/{filename}_ips.txt', 'r') as src:
            lines = src.readlines()
            for line in lines:
                line = line.strip()
                matches = ip_compiled.findall(line)
                for match in matches:
                    dest.write(match+"\n")
    print(f"Updated IPs from {url}")