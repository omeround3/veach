from ast import operator
import imp
from utils import *

# This script will enumerate all existing fields under cpe_match
fields = []

# Get all data from json feed
cve_data = get_cve_records_from_files(2002)

for rec in cve_data:
    id = get_field('cve.CVE_data_meta.ID', rec)
    nodes = get_field('configurations.nodes', rec)
    if nodes:
        for node in nodes:
            if 'operator' in node and 'cpe_match' in node:
                operator = node['operator']
                cpe_match = node['cpe_match']
                if len(cpe_match) > 0:
                    fields.append(f"{operator} : {id} : {len(cpe_match)}")

print_to_file(fields, __file__.replace(".py", ".txt"))
