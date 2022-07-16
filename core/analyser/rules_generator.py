import pickle
from core.analyser.category import Rule
from core.analyser.cvss.cvss_record_template_v3 import *
from core.analyser.enums import Severity
from core.obj.vector_string import VectorString
from core.utils import get_settings_value


def generate_rules():
    rules: list[Rule] = list()
    rules_dict = {}

    attributes = ['attack_vector', 'attack_complexity',
                  'confidentiality_impact', 'integrity_impact', 'availability_impact']
    for attr in attributes:
        rules_dict[attr] = get_settings_value('RULES', attr).split(',')

    for av in rules_dict['attack_vector']:
        vs = VectorString(av=AttackVector[av],
                          ac=AttackComplexity[rules_dict['attack_complexity'][0]],
                          c=ConfidentialityImpact[rules_dict['confidentiality_impact'][0]],
                          i=IntegrityImpact[rules_dict['integrity_impact'][0]],
                          a=AvailabilityImpact[rules_dict['availability_impact'][0]])
        rules.append(Rule(CVSSRecordV3(vs), Severity.HIGH, is_critical=True))

    with open("veach_rules", 'wb') as file:
        rules = pickle.dump(rules, file)
        file.close
