### --- ANALYSER --- ###
import pickle
import json
import csv
import pymongo
import unittest
from core.analyser.rule import Rule
from core.analyser.cvss.cvss_record_template_v3 import *
from core.analyser.enums import *
from core.analyser.analyser import Analyser
from core.obj.cpe_record import CPERecord
from core.obj.cve_record import CVERecord
from core.matcher.matcher import Matcher
from core.matcher.mongo_matcher import MongoMatcher
from core.matcher.tests import *
from core.utils import *
import core.analyser.rules_generator


def print_dict(item: dict):
    print(json.dumps(item, indent=4))


if __name__ == '__main__':

    anal = Analyser()
    print("OK")
    cve = CVERecord({
        "cve": {
            "data_type": "CVE",
            "data_format": "MITRE",
            "data_version": "4.0",
            "CVE_data_meta": {
                "ID": "CVE-2022-20105",
                "ASSIGNER": "security@mediatek.com"
            },
            "problemtype": {
                "problemtype_data": [{
                    "description": [{
                        "lang": "en",
                        "value": "CWE-787"
                    }]
                }]
            },
            "references": {
                "reference_data": [{
                    "url": "https://corp.mediatek.com/product-security-bulletin/May-2022",
                    "name": "https://corp.mediatek.com/product-security-bulletin/May-2022",
                    "refsource": "MISC",
                    "tags": ["Vendor Advisory"]
                }]
            },
            "description": {
                "description_data": [{
                    "lang": "en",
                    "value": "In MM service, there is a possible out of bounds write due to a stack-based buffer overflow. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: DTV03330460; Issue ID: DTV03330460."
                }]
            }
        },
        "configurations": {
            "CVE_data_version": "4.0",
            "nodes": [{
                "operator": "AND",
                "children": [{
                    "operator": "OR",
                    "children": [],
                    "cpe_match": [{
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:o:google:android:9.0:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:o:google:android:10.0:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:o:google:android:11.0:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }]
                }, {
                    "operator": "OR",
                    "children": [],
                    "cpe_match": [{
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9629:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9631:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9632:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9636:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9638:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9639:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9650:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9652:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9669:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9670:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9011:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9215:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9216:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9220:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9221:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9255:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9256:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9266:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9269:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9285:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9286:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9288:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9600:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9602:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9610:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9611:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9675:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9685:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9686:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9688:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9612:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9613:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9615:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9617:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9630:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9666:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }]
                }],
                "cpe_match": []
            }, {
                "operator": "AND",
                "children": [{
                    "operator": "OR",
                    "children": [],
                    "cpe_match": [{
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:o:linux:linux_kernel:4.9:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:o:linux:linux_kernel:4.19:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }]
                }, {
                    "operator": "OR",
                    "children": [],
                    "cpe_match": [{
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9629:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9631:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9632:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9636:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9638:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9639:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9650:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9652:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9669:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9670:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9011:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9215:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9216:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9220:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9221:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9255:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9256:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9266:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9269:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9285:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9286:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9288:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9600:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9602:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9610:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9611:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9675:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9685:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9686:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9688:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9612:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9613:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9615:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9617:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9630:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": False,
                        "cpe23Uri": "cpe:2.3:h:mediatek:mt9666:-:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }]
                }],
                "cpe_match": []
            }]
        },
        "impact": {
            "baseMetricV3": {
                "cvssV3": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                    "attackVector": "LOCAL",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "HIGH",
                    "userInteraction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "HIGH",
                    "availabilityImpact": "HIGH",
                    "baseScore": 6.7,
                    "baseSeverity": "MEDIUM"
                },
                "exploitabilityScore": 0.8,
                "impactScore": 5.9
            },
            "baseMetricV2": {
                "cvssV2": {
                    "version": "2.0",
                    "vectorString": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
                    "accessVector": "LOCAL",
                    "accessComplexity": "LOW",
                    "authentication": "NONE",
                    "confidentialityImpact": "PARTIAL",
                    "integrityImpact": "PARTIAL",
                    "availabilityImpact": "PARTIAL",
                    "baseScore": 4.6
                },
                "severity": "MEDIUM",
                "exploitabilityScore": 3.9,
                "impactScore": 6.4,
                "acInsufInfo": False,
                "obtainAllPrivilege": False,
                "obtainUserPrivilege": False,
                "obtainOtherPrivilege": False,
                "userInteractionRequired": False
            }
        },
        "publishedDate": "2022-05-03T21:15Z",
        "lastModifiedDate": "2022-05-12T02:10Z"
    })

    client = pymongo.MongoClient(
        "mongodb+srv://veach:gfFVGjpGfeayd3Qe@cluster0.gnukl.mongodb.net/?authMechanism=DEFAULT")
    db = client['nvdcve']

    matcher: Matcher = MongoMatcher(db)

    csv_file = open(
        'C:\\Users\\Daniel\\Documents\\veach\\core\\scanner\\fake_scanner.csv')
    cpe_uris = list(csv.reader(csv_file, delimiter=','))

    rec1 = RecordTemplateV3(
        Version.V3_1, AttackVector.LOCAL, AttackComplexity.LOW)
    rule1 = Rule(rec1, Severity.HIGH,
                 "LOCAL_LOW")

    rec2 = RecordTemplateV3(
        Version.V3_1, AttackVector.NETWORK, AttackComplexity.HIGH)
    rule2 = Rule(rec2, Severity.MEDIUM, "HIGH Complex - Network Vuln")

    analyser = Analyser([rule1, rule2])
    # analyser.add(cve)
    # analyser.analyse()

    for cpe_uri in cpe_uris:
        matcher.match(cpe_uri[0].lower())

    if matcher.matches:
        for match in matcher.matches.keys():
            analyser.add(matcher.matches[match])
        analyser.analyse()

    for key in matcher.matches.keys():
        for cve in matcher.matches[key]:
            print(cve._impact)

    print("DONW")
    # # analyser.add(cve)

    # analyser.analyse()
    # cpe1 = CPERecord(
    #     {"cpe23Uri": "cpe:2.3:o:freebsd:freebsd:2.1.7:*:*:*:*:*:*:*"})
    # cpe2 = CPERecord(
    #     {"cpe23Uri": "cpe:2.3:o:freebsd:freebsd:2.1.7:*:*:*:*:*:*:*"})
    # print(cpe1 == cpe2)
    # print("Done")

    ### --- MATCHER --- ###
    # from core.matcher.mongo_matcher import MongoMatcher
    # import pymongo
    # import time

    # if __name__ == "__main__":

    # print(type(db))

    # cpe = "cpe:2.3:o:freebsd:freebsd:1.0:*:*:*:*:*:*:*"
    # cpe_rec = CPERecord(
    #     {Attributes.CPE_23_URI: cpe})
    # m = Matcher()

    # m.match(CPERecord({
    #     "cpe23Uri": "cpe:2.3:a:calamares:calamares:3.1:*:*:*:*:*:*:*"
    # }))

    # client = pymongo.MongoClient(
    #     "mongodb+srv://veach:gfFVGjpGfeayd3Qe@cluster0.gnukl.mongodb.net/?authMechanism=DEFAULT")
    # db = client['nvdcve']
    # my_coll = db['cvedetails']

    # start = time.time()
    # m = MongoMatcher(db)
    # m.match("cpe:2.3:a:google:chrome:6.0.466.2:*:*:*:*:*:*:*")
    # end = time.time()

    # print(end-start)
    # print("DONE")
