from email import utils
from operator import indexOf
import pickle

from core.analyser.cvss.cvss_record_template_v3 import *
from core.analyser.enums import Severity
from core.analyser.rule import Rule
from core.utils import get_settings_value
veach_rules: list[Rule] = []


def add_rule(rule: Rule):
    if rule in veach_rules:
        print(
            f"[ERROR] - Rule already exist: index {veach_rules.index(rule)}")
    else:
        veach_rules.append(rule)


add_rule(Rule(RecordTemplateV3(attack_vector=AttackVector.NETWORK,
                               attack_complexity=AttackComplexity.LOW), Severity.HIGH, "A kid might be able to hack your PC remotly"))

add_rule(Rule(RecordTemplateV3(attack_vector=AttackVector.NETWORK,
                               attack_complexity=AttackComplexity.HIGH), Severity.HIGH, "A ninja hacker might be able to hack your PC remotly"))

file = open(get_settings_value("RULES", "veach_rules"), "wb")
pickle.dump(veach_rules, file)
file.close()
