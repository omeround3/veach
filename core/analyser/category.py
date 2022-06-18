from os import sep
from attr import attr
from core.analyser.cvss.cvss_record_template_v3 import CVSSRecordV3
from core.analyser.enums import CVSSV3Attributes, Severity
from core.errors import *
from core.matcher.enums import CVEAttributes
from core.utils import *
import json
from core.obj.cve_record import CVERecord


class Category:
    """
    A class used to set weighted values to security attributes
    E.G Weight([("attackVector", "NETWORK"),("attackComplexity", "LOW")], HIGH, True) - a CVE with this
    attribute will inherit the severity, regardless of other attributes(!)
    """
    min_weight = None
    max_weight = None

    def __init__(self, record_scheme: CVSSRecordV3, severity: Severity = Severity.MEDIUM, is_critical: bool = False):
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
            with open("core\\analyser\\attributes_mapping.json", "r", encoding='utf-8') as json_file:
                self.attribute_mapping = json.load(json_file)
        except FileNotFoundError as e:
            print(e)
            quit()

        self.affected_records: list[CVERecord] = []
        self.record_scheme = record_scheme
        self.severity = severity
        self.is_critical = is_critical
        self.average = float(0.0)
        self.tag = self.generate_tag()

    def generate_tag(self):
        attr_list = list(self.attribute_mapping.keys())
        tag_list = [str("")]*len(attr_list)

        for key, val in self.record_scheme.vector_string_attributes.items():
            if key in self.attribute_mapping:
                if self.attribute_mapping[key][val + "_prefix"] != "":
                    tag_list[attr_list.index(
                        key)] += str(self.attribute_mapping[key][val + "_prefix"])+" "
                if self.attribute_mapping[key][val] != "":
                    tag_list[attr_list.index(
                        key)] += self.attribute_mapping[key][val]
        self.tag = " ".join(tag_list)
        self.tag = self.tag.replace("\n ", "\n")
        self.tag = self.tag.title()
        return self.tag

    def add_affected_record(self, record: CVERecord) -> None:
        """
        :param record: A record that meets the rule condition/s
        :param score: The record baseScore value from the CVSS
        :return: None
        """

        self.average = self.average + ((float(get_attribute(record.get_metrics(self.record_scheme.type), CVSSV3Attributes.BASE_SCORE)) -
                                        self.average) / (len(self.affected_records) + 1))
        self.affected_records.append(record)

    def get_severity_value(self) -> float:
        """
        :return: Temporary
        """
        delta = Category.max_weight - Category.min_weight
        return Category.min_weight + (self.severity * (delta / (len(Severity) - 1)))

    def __str__(self):
        ret_str = f"[{self.severity}] - {self.tag}\n"
        for rec in self.affected_records:
            ret_str += f"   {rec['cve']['CVE_data_meta']['ID']}\n"
        return ret_str

    def __hash__(self) -> int:
        return self.record_scheme.__hash__()

    def __eq__(self, __o: object) -> bool:
        return self.record_scheme == __o.record_scheme
