import json
from typing import Iterable


def get_cve_records_from_files(start_year):
    cve_data = []
    for i in range(start_year, 2023):
        str = f'core\\research_scripts\\jsons\\nvdcve-1.1-{i}.json'
        tmp = open(str, encoding='utf-8')
        cve_data_22 = json.load(tmp)
        cve_data_22 = cve_data_22["CVE_Items"]
        cve_data = cve_data + cve_data_22
    return cve_data


def get_field(field, record):
    fields = field.split('.')
    for f in fields:
        if f in record:
            record = record[f]
        else:
            print(f"field {f} wasn't found in {record}")
            return None
    return record


def print_to_file(values: Iterable, file_name):
    file = open(file_name, "w")
    for value in values:
        file.write(value+"\n")
    file.close()
