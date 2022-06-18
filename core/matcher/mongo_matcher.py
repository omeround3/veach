import configparser
from gc import collect
from msilib.schema import Error
from core.matcher.matcher import Matcher
from core.errors import MissingConfigFileOption, MissingConfigFileSection
from core.matcher.enums import CPEAttributes
from core.utils import distinct_append_list
from ..obj.cve_record import CVERecord
from ..obj.cpe_record import CPERecord
from pymongo import database
import re


class MongoMatcher(Matcher):

    def __init__(self, database: database.Database = None) -> None:
        """
        A class used to match a CPE URI to CVE records based on database info
        :param database: a mongodb database
        """
        super().__init__(database)
        cfg = configparser.ConfigParser()
        cfg.read('core\\config.ini')

        try:
            self._cpe_path_to_cpe_uri = cfg['MATCHER']['cpe_path_to_cpe_uri']
            self._cve_path_to_cpe_uri = cfg['MATCHER']['cve_path_to_cpe_uri']

            self._cpe_collection_name = cfg['MATCHER']['cpe_collection_name']
            self._cve_collection_name = cfg['MATCHER']['cve_collection_name']

            self._cve_collection = self._database[self._cve_collection_name]
            self._cpe_collection = self._database[self._cpe_collection_name]
        except KeyError as e:
            if e.args[0] == 'ANALYSER':
                raise MissingConfigFileSection(e)
            else:
                raise MissingConfigFileOption(e)

    def match(self, cpe_uri: str):
        """
        match CPE URI to CVE records and place results in "matches" dictionary
        :param cpe_uri: a cpe string 
        """
        cpe_matches = self._get_cpe_matches(cpe_uri)
        if cpe_matches:
            for cpe_match in cpe_matches:
                cve_matches = list(self._get_cve_matches(cpe_match))
                if cve_matches:
                    for cve_match in cve_matches:
                        self.matches[cpe_uri].add(CVERecord(cve_match))
        return self.matches

    def _get_cpe_matches(self, cpe: str):
        result: set(CPERecord) = set()
        query = self._gen_cpe_query_1(cpe)
        result.update(list(map(lambda x: CPERecord(x),
                               self._cpe_collection.find(query, {"_id": 0, "cpe_name": 0}))))

        query = self._gen_cpe_query_2(cpe)
        result.update(list(map(lambda x: CPERecord(x),
                               self._cpe_collection.find(query, {"_id": 0, "cpe_name": 0}))))
        return result

    def _get_cve_matches(self, cpe: CPERecord):
        query = self._gen_cve_query(cpe)
        return self._cve_collection.find(query)

    def _gen_cpe_query_1(self, cpe: str):
        return {self._cpe_path_to_cpe_uri: self._gen_regex_str(cpe)}

    def _gen_cpe_query_2(self, cpe: str):
        return {self._cpe_path_to_cpe_uri.split(".")[1]: self._gen_regex_str(cpe)}

    def _gen_cve_query(self, cpe: CPERecord):
        query = {
            f"{self._cve_path_to_cpe_uri}.{CPEAttributes.CPE_23_URI.value}": str(cpe)}

        if cpe._version_end_excluding:
            query[f"{self._cve_path_to_cpe_uri}.{CPEAttributes.VERSION_END_EXCLUDING.value}"] = cpe._version_end_excluding

        if cpe._version_end_including:
            query[f"{self._cve_path_to_cpe_uri}.{CPEAttributes.VERSION_END_INCLUDING.value}"] = cpe._version_end_including

        if cpe._version_start_excluding:
            query[f"{self._cve_path_to_cpe_uri}.{CPEAttributes.VERSION_START_EXCLUDING.value}"] = cpe._version_start_excluding

        if cpe._version_start_including:
            query[f"{self._cve_path_to_cpe_uri}.{CPEAttributes.VERSION_START_INCLUDING.value}"] = cpe._version_start_including
        return query

    def _gen_regex_str(self, cpe: str):
        ubuntu_regex = re.search("-[0-9.]*ubuntu[0-9.]*", cpe)
        if ubuntu_regex:
            cpe = cpe.replace(ubuntu_regex.group(
                0), "("+ubuntu_regex.group(0)+")?")
        cpe = cpe[:cpe.find(":*:*:*:*:*")]
        cpe = cpe.replace("\\", "\\\\")
        cpe = cpe.replace("$", "\\$")
        cpe = cpe.replace(".", "\\.")

        # PAY ATTENTION TO THE ORDER OF EXECUTION
        cpe = cpe.replace("*", ".*")
        return {"$regex": '^'+cpe}
