import csv

def write_detection(file, fields, dict_list):
    """
    Provide a file path, field list and list of dicts containing appropriate field values.
    :param file:
    :param fields:
    :param dict_list:
    :return:
    """
    with open(file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        for item in dict_list:
            writer.writerow(item)
