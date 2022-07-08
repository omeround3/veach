from core.orchestrator.orchestrator import Orchetrator

orc = Orchetrator()
orc._invoke_authenticator("daniel", "123456")

cpes = orc.invoke_scanner()

print("OK")


# from core.db.sync_collections import *

# dump(["cvedetails", "cpematches"])
# from core.orchestrator.orchestrator import Orchetrator
# from core.orchestrator import *
# from core.matcher.tests import *
# from core.analyser.cvss.cvss_record_template_v3 import *
# from core.analyser.enums import *

# # # --- Connect to DB defined in config

# client = pymongo.MongoClient(get_settings_value("Matcher", "db_client"))

# # # # --- Select DB & Collections from config
# db = client[get_settings_value("Matcher", "db_name")]
# cpe_collection = get_settings_value("Matcher", "cpe_collection_name")
# cve_collection = get_settings_value("Matcher", "cve_collection_name")

# # # # --- Initiallize Matcher
# matcher: Matcher = MongoMatcher(db, cpe_collection, cve_collection)

# request.data = ["cpe:2.3:a:*:accountsservice:0.6.45-1ubuntu1.3:*:*:*:*:*:*:*",
#                 "cpe:2.3:a:*:amd64-microcode:3.20191021.1+really3.20181128.1~ubuntu0.18.04.1:*:*:*:*:*:*:*"]

# analyser = Analyser()

# categories: list[Category] = []

# for uri in request.data:
#     matcher.match(cpe_uri=uri)
#     if matcher.matches[uri]:
#         analyser.add(matcher.matches[uri])

# orchestrator = Orchetrator()

# # will launch scanner + parser and return cpe_list
# cpe_list = orchestrator.invoke_scanner()

# cve_categories = orchestrator.invoke_matcher(cpe_list)

# #mitigation_dict = orchestrator.invoke_mitigator()
# print(cve_categories)
