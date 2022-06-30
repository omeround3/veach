import pickle
from collections import defaultdict
import time
from gc import collect
from core.matcher.matcher import Matcher
from core.matcher.enums import CPEAttributes
from core.utils import *
from ..obj.cve_record import CVERecord
from ..obj.cpe_record import CPERecord
from pymongo import database
import re


class MongoMatcher(Matcher):

    def __init__(self, database: database.Database, cpe_collection: str, cve_collection: str) -> None:
        """
        A class used to match a CPE URI to CVE records based on database info
        :param database: a mongodb database
        """
        super().__init__(database)

        self._cpe_path_to_cpe_uri = get_settings_value(
            "Matcher", "cpe_path_to_cpe_uri")
        self._cve_path_to_cpe_uri = get_settings_value(
            "Matcher", "cve_path_to_cpe_uri")
        self._last_match_file = get_settings_value(
            "Matcher", "last_match_file")

        self._cpe_collection_name = cpe_collection
        self._cve_collection_name = cve_collection

        self._cve_collection = self._database[self._cve_collection_name]
        self._cpe_collection = self._database[self._cpe_collection_name]

        self.matches_cache: defaultdict[str, set[str]] = defaultdict(None)

        try:
            with open(self._last_match_file, "rb") as file:
                self.matches_cache = pickle.load(file)
        except FileNotFoundError:
            pass  # Do nothing

    def match(self, cpe_uri: str) -> dict:
        """
        match CPE URI to CVE records and place results in "matches" dictionary
        :param cpe_uri: a cpe string 
        :return: dictionary [cpe_uri : cve_matches]
        """
        cve_matches = None
        cpe_matches: set[CPERecord] = set()
        matches: dict[str, set[CVERecord]] = defaultdict(set)
        if cpe_uri in self.matches_cache.keys():
            start = time.time()
            for s in self.matches_cache[cpe_uri]:
                cpe_matches.update(self._get_cpe_matches_by_id(s))
            end = time.time()
        else:
            start = time.time()
            cpe_matches = self._get_cpe_matches_by_name(cpe_uri)
            end = time.time()
            self.matches_cache[cpe_uri] = {x._generated_id for x in cpe_matches}
        #print(f"Get CPE: {end-start}")
        if cpe_matches:
            for cpe_match in cpe_matches:
                start = time.time()
                cve_matches = list(self._get_cve_matches(cpe_match))
                end = time.time()
                #print(f"Get CVE: {end-start}")
                if cve_matches:
                    cve_matches = list(
                        map(lambda x: CVERecord(x), cve_matches))
                    for cve_match in cve_matches:
                        matches[cpe_uri].add(cve_match)
        self._save_cache()
        return matches

    def _save_cache(self) -> None:
        """saves last_match dictionary to file"""
        with open(self._last_match_file, "wb") as file:
            pickle.dump(self.matches_cache, file)

    def _get_cpe_matches_by_id(self, id: str) -> list:
        """
        Get all CPE matches by id
        :param id: unique id of a cpe match record
        :return: list of CPERecords
        """
        query = {"_id": id}
        return (list(map(lambda x: CPERecord(x),
                         self._cpe_collection.find(query, {"cpe_name": 0}))))

    def _get_cpe_matches_by_name(self, cpe: str) -> list:
        """
        Get all CPE matches by URI
        :param cpe: CPE 2.3 URI
        :return: list of CPERecords
        """
        result: set(CPERecord) = set()
        query = self._gen_cpe_query_1(cpe)
        result.update(list(map(lambda x: CPERecord(x),
                               self._cpe_collection.find(query, {"cpe_name": 0}))))

        query = self._gen_cpe_query_2(cpe)
        result.update(list(map(lambda x: CPERecord(x),
                               self._cpe_collection.find(query, {"cpe_name": 0}))))

        return result

    def _get_cve_matches(self, cpe: CPERecord) -> list:
        """
        Get all CVE records by CPE match
        :param cpe: CPERecord
        :return: list of CVE Records
        """
        query = self._gen_cve_query(cpe)
        return self._cve_collection.find(query)

    def _gen_cpe_query_1(self, cpe: str) -> str:
        """
        Generate CPE query for finding a match in cpe_names array
        :param cpe: CPE 2.3 URI
        :return: query string for PyMongo
        """
        return {self._cpe_path_to_cpe_uri: self._gen_regex_str(cpe)}

    def _gen_cpe_query_2(self, cpe: str) -> str:
        """
        Generate CPE query for finding a match in cpe23Uri field
        :param cpe: CPE 2.3 URI
        :return: query string for PyMongo
        """
        return {self._cpe_path_to_cpe_uri.split(".")[1]: self._gen_regex_str(cpe)}

    def _gen_cve_query(self, cpe: CPERecord) -> str:
        """
        Generate regex string for MongoDB CVE search
        :param cpe: CPERecord        
        :return: query string for PyMongo        
        """
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

    def _gen_regex_str(self, cpe: str) -> str:
        """
        Generate regex string for MongoDB CPE search with wildcards
        :param cpe: CPE 2.3 URI
        :return: regex string for PyMongo
        """
        ubuntu_match = re.search("-[0-9.]*ubuntu[0-9.]*", cpe)
        if ubuntu_match:
            cpe = cpe.replace(ubuntu_match.group(
                0), "("+ubuntu_match.group(0)+")?")

        cpe = cpe.replace("\\", "\\\\")
        cpe = cpe.replace("$", "\\$")
        cpe = cpe.replace(".", "\\.")
        cpe = cpe.replace(":h:", ":.:")
        # PAY ATTENTION TO THE ORDER OF EXECUTION
        cpe = cpe.replace("*", ".*")

        suffix_match = re.search(r"(\:\.\*)+$", cpe)
        if suffix_match:
            cpe = cpe.replace(suffix_match.group(
                0), ":.*")
        return {"$regex": '^'+cpe}
