import time
from core import orchestrator
from core.mitigator.mitigator import Mitigator
from core.orchestrator.orchestrator import Orchetrator


# class Test():
#     def __init__(self, time) -> None:
#         self.time = time
#         self.vals = []

#     def wait(self):
#         for i in range(1000):
#             time.sleep(self.time)
#             self.vals.append(i)
#             print(i, " Added")

#     def get_vals(self):
#         return self.vals


orchestrator = Orchetrator()
# test = Test(5)

# import pymongo
# import csv
# from core.utils import *
# from core.matcher.matcher import Matcher
# from core.matcher.mongo_matcher import MongoMatcher
# from core.analyser.analyser import Analyser

# # # --- Connect to DB defined in config

# client = pymongo.MongoClient(get_settings_value("Matcher", "db_client"))

# # # # --- Select DB & Collections from config
# db = client[get_settings_value("Matcher", "db_name")]
# cpe_collection = get_settings_value("Matcher", "cpe_collection_name")
# cve_collection = get_settings_value("Matcher", "cve_collection_name")

# # # --- Initiallize Matcher
# matcher: MongoMatcher = MongoMatcher(db, cpe_collection, cve_collection)

# analyser = Analyser()
# # # # --- Initiallize Matcher
# matcher: Matcher = MongoMatcher(db, cpe_collection, cve_collection)
