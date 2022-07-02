

import pickle
from core.analyser.category import Rule
from core.analyser.cvss.cvss_record_template_v3 import *
from core.analyser.enums import Severity
from core.obj.vector_string import VectorString


rules: set[Rule] = set()

rules.add(Rule(CVSSRecordV3(VectorString(av=AttackVector.NETWORK,
                            ac=AttackComplexity.HIGH,
                            pr=None,
                            ui=None,
                            s=None,
                            c=None,
                            i=None,
                            a=None)), severity=Severity.LOW, is_critical=True))


with open("veach_rules", 'wb') as file:
    rules = pickle.dump(list(rules), file)
    file.close
