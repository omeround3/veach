### --- ANALYSER --- ###
import pickle
import json
import csv
from unicodedata import category
import pymongo
import unittest
import time
from core import analyser
from core.analyser.category import Category, Rule
from core.analyser.cvss.cvss_record_template_v3 import *
from core.analyser.enums import *
from core.analyser.analyser import Analyser
from core.matcher.matcher import Matcher
from core.matcher.mongo_matcher import MongoMatcher
from core.matcher.tests import *
from core.utils import *

from core.analyser.cvss.cvss_record_template_v3 import CVSSRecordV3


def print_dict(item: dict):
    print(json.dumps(item, indent=4))


if __name__ == '__main__':

    # client = pymongo.MongoClient(
    #     "mongodb+srv://veach:gfFVGjpGfeayd3Qe@cluster0.gnukl.mongodb.net/?authMechanism=DEFAULT")
    # client = pymongo.MongoClient("localhost", 27017)

    # db = client['VEACH']

    # matcher: Matcher = MongoMatcher(db)
    # cpe_uris = []
    # csv_file = open(
    #     'C:\\Users\\Daniel\\Documents\\veach\\core\\scanner\\fake_scanner.csv')
    # reader = csv.reader(csv_file, delimiter=',')
    # for row in reader:
    #     cpe_uris.append(row[0].lower())

    # analyser = Analyser()
    # counter = 0
    # for cpe_uri in cpe_uris:
    #     start = time.time()
    #     matcher.match(cpe_uri.lower())
    #     end = time.time()
    #     print(counter, ":", end-start)
    #     counter += 1

    # if matcher.matches:
    #     for key in matcher.matches.keys():
    #         analyser.add(matcher.matches[key])
    #     # analyser.analyse()

    analyser = Analyser()
    # pic = analyser.records
    file = open("records", "rb")
    records = pickle.load(file)
    file.close()

    analyser.add(records)
    analyser.analyse()
    count = 0

    for record in records:
        print(count, " - ", record._id)
        count += 1

    for key in analyser.cve_categories.keys():
        category = analyser.cve_categories[key]
        print(category.tag)
        if category.affected_records:
            for cve in category.affected_records:
                print(" "+str(cve._id))
        else:
            print(" None")
    print("DONE")
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
