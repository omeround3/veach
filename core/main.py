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
    client = pymongo.MongoClient(
        "mongodb+srv://veach:gfFVGjpGfeayd3Qe@cluster0.gnukl.mongodb.net/?authMechanism=DEFAULT")
    db = client['nvdcve']

    matcher: Matcher = MongoMatcher(db)

    csv_file = open(
        'C:\\Users\\Daniel\\Documents\\veach\\core\\scanner\\fake_scanner.csv')
    cpe_uris = list(csv.reader(csv_file, delimiter=','))

    analyser = Analyser()

    for cpe_uri in cpe_uris:
        matcher.match(cpe_uri[0].lower())

    if matcher.matches:
        for key in matcher.matches.keys():
            analyser.add(matcher.matches[key])
        analyser.analyse()

    for rule in analyser.rules:
        print(rule.tag)
        if rule.affected_records:
            for cve in rule.affected_records:
                print(" "+str(cve._id))
        else:
            print(" None")
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
