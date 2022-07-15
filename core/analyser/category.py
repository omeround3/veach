import logging
from os import sep
from core.analyser.cvss.cvss_record_template_v3 import CVSSRecordV3
from core.analyser.enums import CVSSV3Attributes, Severity
from core.errors import *
from core.matcher.enums import CVEAttributes
from core.utils import *
import json
from core.obj.cve_record import CVERecord

logger = logging.getLogger("veach")
class Rule:
    """
    A class used to set Rules to compare with categories, if category meets rule, it inherits the rule sevirity
    """

    def __init__(self, record_scheme: CVSSRecordV3, severity: Severity = Severity.MEDIUM, is_critical: bool = False):
        """
        :param record_scheme: CVSS record with critical attributes
        :param severity: Determine the weight of those attributes
        :param is_critical: if True, the CVE record severity will be same as the attributes severity
        """
        self.record_scheme = record_scheme
        self.severity = severity
        self.is_critical = is_critical

    def __hash__(self) -> int:
        return self.record_scheme.__hash__()

    def __eq__(self, __o: object) -> bool:
        return self.record_scheme == __o.record_scheme


class Category(Rule):
    """
    A class used to set weighted values to security attributes
    E.G Weight([("attackVector", "NETWORK"),("attackComplexity", "LOW")], HIGH, True) - a CVE with this
    attribute will inherit the severity, regardless of other attributes(!)
    """
    min_weight = None
    max_weight = None
    attribute_mapping = None

    def __init__(self, record_scheme: CVSSRecordV3, severity: Severity = Severity.MEDIUM, is_critical: bool = False) -> None:
        """
        :param record_scheme: CVSS record with critical attributes
        :param severity: Determine the weight of those attributes
        :param tag: A string which describe the rule
        :param is_critical: if True, the CVE record severity will be same as the attributes severity
        """
        if Category.min_weight is None or Category.max_weight is None:
            Category.min_weight = float(
                get_settings_value('RULE', 'min_weight'))
            Category.max_weight = float(
                get_settings_value('RULE', 'max_weight'))
            try:
                with open("core/analyser/attributes_mapping.json", "r", encoding='utf-8') as json_file:
                    Category.attribute_mapping = json.load(json_file)
            except Exception as err:
                logger.error(f"[CATEGORY] FileNotFoundError")
                quit()
                

        super().__init__(record_scheme, severity, is_critical)
        self.rules: list[Rule] = []
        self.affected_records: set[CVERecord] = set()
        self.average = float(0.0)
        self.tag = self.generate_tag()

    def generate_tag(self) -> str:
        """
        Genereate a text describing the category
        :return: a string of the description
        """
        attr_list = list(Category.attribute_mapping.keys())
        tag_list = [str("")]*len(attr_list)

        for key, val in self.record_scheme.vector_string_attributes.items():
            if key in Category.attribute_mapping:
                if Category.attribute_mapping[key][val + "_prefix"] != "":
                    tag_list[attr_list.index(
                        key)] += str(Category.attribute_mapping[key][val + "_prefix"])+" "
                if Category.attribute_mapping[key][val] != "":
                    tag_list[attr_list.index(
                        key)] += Category.attribute_mapping[key][val]
        self.tag = " ".join(tag_list)
        self.tag = self.tag.replace("\n ", "\n")
        self.tag = self.tag.title()
        return self.tag

    def add_affected_record(self, record: CVERecord) -> bool:
        """
        :param record: A record that meets the rule condition/s
        :param score: The record baseScore value from the CVSS
        :return: None
        """
        metric = record.get_metrics(self.record_scheme.type)
        if metric:
            base_score = float(get_attribute(
                metric, CVSSV3Attributes.BASE_SCORE))
            if base_score:
                self.average = self.average + \
                    ((base_score - self.average) / (len(self.affected_records) + 1))
                self.affected_records.add(record)
                return True
        return False

    def get_severity_value(self) -> float:
        """
        :return: Temporary
        """
        delta = Category.max_weight - Category.min_weight
        return Category.min_weight + (self.severity * (delta / (len(Severity) - 1)))

    def meets(self, rule: Rule) -> bool:
        """
        Checks if this Category meets the conditions of a certain Rule, if so, the Category Severity will be changed accordingly
        :param rule: Rule class
        :return: True if category meets rule conditions, otherwise, False
        """
        ret_val = False
        if self.record_scheme.meets(rule.record_scheme):
            ret_val = True
            self.rules.append(rule)
            if not self.is_critical and rule.is_critical:
                self.is_critical = rule.is_critical

            if rule.severity > self.severity:
                self.severity = rule.severity
        return ret_val

    def __str__(self) -> str:
        ret_str = f"[{self.severity}] - {self.tag}\n"
        for rec in self.affected_records:
            ret_str += f"   {rec['cve']['CVE_data_meta']['ID']}\n"
        return ret_str
