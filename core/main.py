from core.analyser.cvss.cvss_record_template_v3 import *
from core.analyser.enums import *


from core.matcher.tests import *
from core.orchestrator import *
from core.orchestrator.orchestrator import Orchetrator

orchestrator = Orchetrator()
 
orchestrator.invoke_scanner()



