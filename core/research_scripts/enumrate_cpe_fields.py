import imp
from utils import *

# This script will enumerate all existing fields under cpe_match
fields = set()

# Get all data from json feed
cve_data = get_cve_records_from_files(2022)

for rec in cve_data:
    nodes = get_field('configurations.nodes', rec)
    if nodes:
        for node in nodes:
            cpe_matches = get_field('cpe_match', node)
            for match in cpe_matches:
                for key in match.keys():
                    fields.add(key)

print_to_file(fields, __file__.replace(".py", ".txt"))
