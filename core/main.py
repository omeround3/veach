import pymongo
import csv

from requests import request
from core.analyser.category import Category
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
matcher: Matcher = MongoMatcher(db, cpe_collection, cve_collection)

request.data = ["cpe:2.3:a:*:accountsservice:0.6.45-1ubuntu1.3:*:*:*:*:*:*:*",
                "cpe:2.3:a:*:amd64-microcode:3.20191021.1+really3.20181128.1~ubuntu0.18.04.1:*:*:*:*:*:*:*"]

analyser = Analyser()

categories: list[Category] = []

for uri in request.data:
    matcher.match(cpe_uri=uri)
    if matcher.matches[uri]:
        analyser.add(matcher.matches[uri])
