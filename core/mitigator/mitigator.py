import requests
import re
from core.db.db_utils import get_local_db
from core.matcher.matcher import Matcher
from core.analyser.analyser import Analyser
from core.matcher.mongo_matcher import MongoMatcher
from core.obj.cpe_record import CPERecord
from core.obj.cve_record import CVERecord
from core.utils import get_settings_value
from core.parser.parser import Parser
from core.utils import get_attribute
from core.analyser.enums import CVSSV3Attributes


class Mitigator:
    """
    A class used to find mitigations for vulnerabilities
    """

    def __init__(self, parser: Parser) -> None:
        """
        :param matcher: A Matcher instance we want to find mitigation in
        :param parser: A Parser instance
        """
        self.db = get_local_db()[0]
        self.cpe_collection = get_settings_value(
            "COLLECTIONS", "cpe_collection_name")
        self.cve_collection = get_settings_value(
            "COLLECTIONS", "cve_collection_name")
        self.matcher = MongoMatcher(
            self.db, self.cpe_collection, self.cve_collection)
        self.parser = parser

    def _get_alterntive_sources(self, cpe: CPERecord):
        """
        Get available version for a specific product for the linux distro installed
        :param cpe: a CPERecord for which we want to find available versions
        """
        linux_distro = get_settings_value("Mitigator", "linux_distro")
        package_name = cpe._product
        package_version = cpe._version
        ubuntu_match = re.search("-[0-9.]*ubuntu[0-9.]*", package_version)
        if ubuntu_match:
            package_version = package_version.replace(
                ubuntu_match.group(0), "")
        versions = requests.get(
            f"https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name={package_name}&exact_match=true").json()["entries"]

        versions = list(filter(
            lambda x: linux_distro in x["distro_series_link"], versions))

        versions = list(filter(
            lambda x: package_version not in x["source_package_version"], versions))

        for v in versions:
            ubuntu_match = re.search(
                "-[0-9.]*ubuntu[0-9.]*", v["source_package_version"])
            if ubuntu_match:
                v["source_package_version"] = v["source_package_version"].replace(
                    ubuntu_match.group(0), "")
        return versions

    def mitigate_package(self, cpe: CPERecord) -> dict:
        """
        Find mitigations for a product installed 
        :param cpe: a CPERecord for which we want to find mitigations
        :return: a dict with the categories of the mitigations found
        """
        mitigation_dict = dict()
        cve_matches: set[CVERecord] = set()
        sources = self._get_alterntive_sources(cpe)
        if not sources:
            return None

        analyser = Analyser()
        cpe_uris = self.parser.parse_data_to_cpe([{"part": "a", "vendor": None, "product": cpe._product,
                                                   "version": x["source_package_version"]}for x in sources])

        for cpe in cpe_uris:
            mitigation_dict[cpe] = self.matcher.match(cpe)[cpe]
            if mitigation_dict[cpe]:
                cve_matches.update(mitigation_dict[cpe])

        if cve_matches:
            cve_categories = analyser.analyse(cve_matches)

        for cpe, cves in mitigation_dict.items():
            categories = []
            if cves:
                for cve in cves:
                    vector_string = get_attribute(
                        cve.get_metrics(), CVSSV3Attributes.VECTOR_STRING)
                    if vector_string:
                        categories.append(cve_categories[vector_string])
                mitigation_dict[cpe] = list(categories)
        return mitigation_dict
