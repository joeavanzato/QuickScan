
import csv
def parse(file):
    """
    Returns a list of dictionaries - 1 dictionary per row for specified CSV files.
    :param file:
    :return:
    """
    temp_list = []
    fields = []
    with open(file, 'r') as f:
        reader = csv.reader(f)
        i = 0
        for r in reader:
            tdict = {}
            if i == 0:
                for y in range(len(r)):
                    fields.append(r[y])
                i += 1
            else:
                for y in range(len(r)):
                    tdict[fields[y]] = r[y]
                temp_list.append(tdict)
    return temp_list
