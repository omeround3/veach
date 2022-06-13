from core.analyser.enums import BaseMetricAttributes
from core.analyser.rule import Rule
from core.obj.cve_record import CVERecord
from typing import List

class Analyser:

    def __init__(self, rules: List[Rule] = [], base_metric: BaseMetricAttributes = BaseMetricAttributes.V3):
        """
        A class used to analyse and evaluate the risk of the existing CVEs
        :param rules: List of rules which every record will be compared and categorised to
        :param base_metric: Determine which Common Vulnerability Scoring System (CVSS) will be used
        """
        self.records: list[CVERecord] = []
        self.base_metric = base_metric
        self.rules = rules

    def add(self, records: List[CVERecord]):
        """
        Adds a CVE record to the analyser engine
        :param record: a CVE record to add for analysis
        :return: None
        """
        self.records.append(records)

    def analyse(self):
        """
        Perform the analysis on records added to the analyser engine
        :return:
        """
        for record in self.records:
            base_metrics = record.get_metrics(self.base_metric)
            if base_metrics:
                if 'cvss' + self.base_metric.name in base_metrics:
                    cvss = base_metrics['cvss' + self.base_metric.name]
                    if 'baseScore' in cvss and 'vectorString' in cvss:
                        base_score = cvss['baseScore']
                        vector_string = cvss['vectorString']
            if vector_string and base_score:
                for rule in self.rules:
                    record_scheme = rule.record_scheme
                    if all(x in vector_string for x in record_scheme.vector_string_attributes):
                        rule.add_affected_record(record, base_score)
