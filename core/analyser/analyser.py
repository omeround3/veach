from enums import CVSS
from rule import Rule


class Analyser:

    def __init__(self, rules: list[Rule] = [], base_metric: CVSS = CVSS.V3):
        """
        A class used to analyse and evaluate the risk of the existing CVEs
        :param rules: List of rules which every record will be compared and categorised to
        :param base_metric: Determine which Common Vulnerability Scoring System (CVSS) will be used
        """
        self.base_metric = base_metric
        self.records = []
        self.rules = rules

    def add(self, record: dict):
        """
        Adds a CVE record to the analyser engine
        :param record: a CVE record to add for analysis
        :return: None
        """
        self.records.append(record)

    def analyse(self):
        """
        Perform the analysis on records added to the analyser engine
        :return:
        """
        for record in self.records:
            if 'impact' in record:
                record_impact = record['impact']
                if self.base_metric.value in record_impact:
                    base_metric = record_impact[self.base_metric.value]
                    if 'cvss' + self.base_metric.name in base_metric:
                        cvss = base_metric['cvss' + self.base_metric.name]
                        if 'baseScore' in cvss and 'vectorString' in cvss:
                            base_score = cvss
                            vector_string = cvss['vectorString']
            if vector_string and base_score:
                for rule in self.rules:
                    record_scheme = rule.record_scheme
                    if all(x in vector_string for x in record_scheme.vector_string_attributes):
                        rule.add_affected_record(record, base_score)
