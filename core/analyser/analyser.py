from collections import defaultdict
import pickle

from core.analyser.cvss.cvss_record_template_v3 import CVSSRecordV3
from core.analyser.enums import BaseMetricAttributes, CVSSV3Attributes
from core.analyser.category import Category
from core.errors import InvalidCVEFormat
from core.obj.cve_record import CVERecord
from core.utils import get_attribute, get_settings_value


class Analyser:

    def __init__(self, base_metric: BaseMetricAttributes = BaseMetricAttributes.V3):
        """
        A class used to analyse and evaluate the risk of the existing CVEs
        :param rules: List of rules which every record will be compared and categorised to
        :param base_metric: Determine which Common Vulnerability Scoring System (CVSS) will be used
        """
        self.records: set[CVERecord] = set()
        self.base_metric = base_metric

        self.priority_categories: set[Category] = set()
        self.cve_categories: dict[str, Category] = defaultdict(lambda: None)

        self._load_rules_from_files()

    def _load_rules_from_files(self, override: bool = False):
        pass
        # if override:
        #     self.priority_categories = []
        # file = open(get_settings_value("RULES", "veach_rules"), 'rb')
        # self.priority_categories += (pickle.load(file))
        # file.close
        # return self.priority_categories

    def add(self, records: set[CVERecord]):
        """
        Adds a CVE record to the analyser engine
        :param record: a CVE record to add for analysis
        :return: None
        """
        self.records.update(records)

    def analyse(self):
        """
        Perform the analysis on records added to the analyser engine
        :return:
        """
        for record in self.records:
            base_metrics = record.get_metrics(self.base_metric)
            if base_metrics:
                base_score = get_attribute(
                    base_metrics, CVSSV3Attributes.BASE_SCORE)
                vector_string = get_attribute(
                    base_metrics, CVSSV3Attributes.VECTOR_STRING)
            if vector_string and base_score:
                self.cve_categories[vector_string] = Category(
                    CVSSRecordV3(vector_string))
                self.cve_categories[vector_string].add_affected_record(record)
                # for rule in self.rules:
                #     record_scheme = rule.record_scheme
                #     if all(x in vector_string for x in record_scheme.vector_string_attributes):
                #         rule.add_affected_record(record)
