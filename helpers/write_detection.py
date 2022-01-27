import csv

def write_detection(file, fields, dict_list):
    """
    Provide a file path, field list and list of dicts containing appropriate field values.
    Dicts should have the following fields, which are also passed to this function as a list as 'fields';
        'Name'
        'Reason'
        'File Path'
        'Registry Path'
        'MITRE Tactic'
        'MITRE Technique'
        'Risk'
        'Details'
    :param file:
    :param fields:
    :param dict_list:
    :return:
    """
    with open(file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        for item in dict_list:
            writer.writerow(item)
