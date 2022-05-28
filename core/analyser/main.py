import json
from cvss.cvss_record_template_v3 import *
from rule import *
from analyser import Analyser


def print_dict(item: dict):
    print(json.dumps(item, indent=4))


if __name__ == '__main__':
    rec1 = RecordTemplateV3(Version.V3_1, AttackVector.NETWORK, AttackComplexity.LOW)
    rule1 = Rule(rec1, Severity.HIGH, "Someone can easliy access your PC from outside")

    rec2 = RecordTemplateV3(Version.V3_1, AttackVector.NETWORK, AttackComplexity.HIGH)
    rule2 = Rule(rec2, Severity.MEDIUM, "HIGH Complex - Network Vuln")

    analyser = Analyser([rule1, rule2])

    cve_data = []
    for i in range(2022, 2023):
        str = f'jsons/nvdcve-1.1-{i}.json'
        cve_file_22 = open(str, encoding='utf-8')
        cve_data_22 = json.load(cve_file_22)
        # test = Analyser()
        cve_data_22 = cve_data_22["CVE_Items"]
        cve_data = cve_data + cve_data_22

#     flag_v3 = True
#
#     flag_v2 = True
#
#     for record in cve_data:
#         if 'impact' not in record:
#             record_impact = record['impact']
#             if 'baseMetricV3' in record_impact:
#                 base_metric = record_impact['baseMetricV3']
#                 if 'cvssV3' in base_metric:
#                     cvss = base_metric['cvssV3']
#                     if 'baseScore' in cvss.keys():
#                         base_score = float(cvss['baseScore'])
#                         if base_score <= 0:
#                             print(record['cve']['CVE_data_meta']['ID'])
#                     else:
#                         flag_v3 = False
#
#     for record in cve_data:
#         if 'impact' in record:
#             record_impact = record['impact']
#             if 'baseMetricV2' in record_impact:
#                 base_metric = record_impact['baseMetricV2']
#                 if 'cvssV2' in base_metric:
#                     cvss = base_metric['cvssV2']
#                     if 'baseScore' in cvss.keys():
#                         base_score = float(cvss['baseScore'])
#                         if base_score <= 0:
#                             print(record['cve']['CVE_data_meta']['ID'])
#                     else:
#                         flag_v2 = False
#
# print('Done')
# for i in range(0, len(cve_data), 17):
#     analyser.add(cve_data[i])
# analyser.analyse()
#
print(rule1)
print(rule2)

# v3_headers = {}
# v2_headers = {}
# for i in cve_data:
#     if 'baseMetricV3' in i['impact'].keys():
#         tmp = dict(i['impact']['baseMetricV3']['cvssV3'])
#         for j in tmp.keys():
#             if j not in v3_headers.keys():
#                 v3_headers[j] = set()
#             v3_headers[j].add(tmp[j])
#
#     if 'baseMetricV2' in i['impact'].keys():
#         tmp = dict(i['impact']['baseMetricV2']['cvssV2'])
#         for j in tmp.keys():
#             if j not in v2_headers.keys():
#                 v2_headers[j] = set()
#             v2_headers[j].add(tmp[j])
#
# print("V2 Headers: ")
# for key, value in v2_headers.items():
#     upper = key[0].upper() + key[1::]
#     print(f"class {upper}(Enum):")
#     for v in value:
#         print(f"    {v} = '{v}'")
#     print("\n\n")
#
# print("V3 Headers: ")
# for key, value in v3_headers.items():
#     upper = key[0].upper() + key[1::]
#     print(f"class {upper}(Enum):")
#     for v in value:
#         print(f"    {v} = '{v}'")
#     print("\n\n")
