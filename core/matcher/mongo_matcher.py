import configparser
from gc import collect
from msilib.schema import Error
from core.matcher.matcher import Matcher
from core.errors import MissingConfigFileOption, MissingConfigFileSection
from core.matcher.enums import CPEAttributes
from ..obj.cve_record import CVERecord
from ..obj.cpe_record import CPERecord
from pymongo import database


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
                cve_matches = self._get_cve_matches(CPERecord(cpe_match))
                if cve_matches:
                    for cve_match in cve_matches:
                        try:
                            self.matches[cpe_uri].add(CVERecord(cve_match))
                        except KeyError:
                            self.matches[cpe_uri] = set()
                            self.matches[cpe_uri].add(CVERecord(cve_match))
        return self.matches

    def _get_cpe_matches(self, cpe: str):
        query = self._gen_cpe_query(cpe)
        return self._cpe_collection.find(query)

    def _get_cve_matches(self, cpe: CPERecord):
        query = self._gen_cve_query(cpe)
        return self._cve_collection.find(query)

    def _gen_cpe_query(self, cpe: str):
        return {self._cpe_path_to_cpe_uri: cpe}

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
