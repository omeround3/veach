# from email import utils
# from operator import indexOf
# import pickle

# from core.analyser.cvss.cvss_record_template_v3 import *
# from core.analyser.enums import Severity
# from core.analyser.category import Category
# from core.utils import get_settings_value
# veach_rules: list[Category] = []


# def add_rule(rule: Category):
#     if rule in veach_rules:
#         print(
#             f"[ERROR] - Category already exist: index {veach_rules.index(rule)}")
#     else:
#         veach_rules.append(rule)


# add_rule(Category(CVSSRecordV3(attack_vector=AttackVector.NETWORK,
#                            attack_complexity=AttackComplexity.LOW), Severity.HIGH))

# add_rule(Category(CVSSRecordV3(attack_vector=AttackVector.LOCAL,
#                            attack_complexity=AttackComplexity.LOW), Severity.HIGH))

# add_rule(Category(CVSSRecordV3(attack_vector=AttackVector.NETWORK,
#                            attack_complexity=AttackComplexity.LOW, confidentiality_impact=ConfidentialityImpact.NONE), Severity.HIGH))


# file = open(get_settings_value("RULES", "veach_rules"), "wb")
# pickle.dump(veach_rules, file)
# file.close()
