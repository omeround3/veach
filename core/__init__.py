import pymongo
import csv
from core.utils import *
from core.matcher.matcher import Matcher
from core.matcher.mongo_matcher import MongoMatcher
from core.analyser.analyser import Analyser
from django.core.cache import caches

# # --- Connect to DB defined in config

client = pymongo.MongoClient(get_settings_value("Matcher", "db_client"))

# # # --- Select DB & Collections from config
db = client[get_settings_value("Matcher", "db_name")]
cpe_collection = get_settings_value("Matcher", "cpe_collection_name")
cve_collection = get_settings_value("Matcher", "cve_collection_name")

# # # --- Initiallize Matcher
matcher: MongoMatcher = MongoMatcher(db, cpe_collection, cve_collection)

analyser = Analyser()
