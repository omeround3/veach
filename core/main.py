from core.analyser.cvss.cvss_record_template_v3 import *
from core.analyser.enums import *


from core.matcher.tests import *
from core.orchestrator import *
from core.orchestrator.orchestrator import Orchetrator

orchestrator = Orchetrator()

# will launch scanner + parser and return cpe_list 
cpe_list = orchestrator.invoke_scanner()

cve_categories = orchestrator.invoke_matcher(cpe_list)

#mitigation_dict = orchestrator.invoke_mitigator()
print(cve_categories)
