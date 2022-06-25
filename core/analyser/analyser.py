from collections import defaultdict
import pickle

from core.analyser.cvss.cvss_record_template_v3 import AttackComplexity, AttackVector, CVSSRecordV3, UserInteraction
from core.analyser.enums import BaseMetricAttributes, CVSSV3Attributes, Severity
from core.analyser.category import Category, Rule
from core.errors import InvalidCVEFormat
from core.obj.cve_record import CVERecord
from core.obj.vector_string import VectorString
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

        self.cve_categories: dict[str, Category] = defaultdict(None)

        self.rules = self._load_rules_from_files()

    def _load_rules_from_files(self) -> None:
        """
        Loads rules defined in setting to mark CVE Records
        :return: None
        """
        file = open("core\\analyser\\veach_rules", 'rb')
        rules = pickle.load(file)
        file.close
        return rules

    def add(self, records: set[CVERecord]) -> None:
        """
        Adds a CVE record to the analyser engine
        :param record: a CVE record to add for analysis
        """
        self.records.update(records)

    def get_cve_category(self, cve: CVERecord) -> Category:
        vector_string = get_attribute(
            cve.get_metrics(), CVSSV3Attributes.VECTOR_STRING)
        return self.cve_categories[vector_string]

    def analyse(self) -> dict:
        """
        Perform the analysis on records added to the analyser engine
        :return: dictionary of CVE categories and CVE Records
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
                    if not self.cve_categories[vector_string].add_affected_record(record):
                        del self.cve_categories[vector_string]
                    else:
                        for rule in self.rules:
                            self.cve_categories[vector_string].meets(rule)
        return self.cve_categories
