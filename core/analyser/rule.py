from core.analyser.enums import Severity
from core.errors import *
from core.analyser.cvss.cvss_record_template import RecordTemplate
from core.utils import *

from core.obj.cve_record import CVERecord


class Rule:
    """
    A class used to set weighted values to security attributes
    E.G Weight([("attackVector", "NETWORK"),("attackComplexity", "LOW")], HIGH, True) - a CVE with this
    attribute will inherit the severity, regardless of other attributes(!)
    """
    min_weight = None
    max_weight = None

    def __init__(self, record_scheme: RecordTemplate, severity: Severity, tag: str = None, is_critical: bool = False):
        """
        :param record_scheme: CVSS record with critical attributes
        :param severity: Determine the weight of those attributes
        :param tag: A string which describe the rule
        :param is_critical: if True, the CVE record severity will be same as the attributes severity
        """
        if Rule.min_weight is None or Rule.max_weight is None:

            Rule.min_weight = float(
                settings_value(self.__name__, 'min_weight'))
            Rule.max_weight = float(
                settings_value(self.__name__, 'max_weight'))

        self.affected_records: list[CVERecord] = []
        self.record_scheme = record_scheme
        self.severity = severity
        self.is_critical = is_critical
        self.tag = tag
        self.average = float(0.0)

    def add_affected_record(self, record, score) -> None:
        """
        :param record: A record that meets the rule condition/s
        :param score: The record baseScore value from the CVSS
        :return: None
        """
        self.average = self.average + \
            ((score - self.average) / (len(self.affected_records) + 1))
        self.affected_records.append(record)

    def get_severity_value(self) -> float:
        """
        :return: Temporary
        """
        delta = Rule.max_weight - Rule.min_weight
        return Rule.min_weight + (self.severity * (delta / (len(Severity) - 1)))

    def __str__(self):
        ret_str = f"[{self.severity}] - {self.tag}\n"
        for rec in self.affected_records:
            ret_str += f"   {rec['cve']['CVE_data_meta']['ID']}\n"
        return ret_str
