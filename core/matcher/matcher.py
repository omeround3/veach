from gc import collect
from msilib.schema import Error
from ..obj.cve_record import CVERecord
from ..obj.cpe_record import CPERecord
from pymongo import database
from core.matcher.fake_db import FakeCPE


class Matcher:

    def __init__(self, database: database.Database = None) -> None:
        self.database = database
        self.matches = dict()

        # DELETE THIS WHEN THERE IS CPE IN DB
        self.fake = FakeCPE(
            "C:\\Users\\Daniel\\Downloads\\nvdcpematch-1.0.json")

    def match(self, cpe: str):
        cpe_matches = self._get_cpe_matches(cpe)
        if cpe_matches:
            for cpe_match in cpe_matches:
                cve_matches = self._get_cve_matches(cpe_match)
                if cve_matches:
                    for cve_match in cve_matches:
                        try:
                            self.matches[cpe].add(cve_match['_id'])
                        except KeyError:
                            self.matches[cpe] = set()
                            self.matches[cpe].add(cve_match['_id'])

        else:
            return None

    def _get_cpe_matches(self, cpe: CPERecord):
        return self.fake._find_cpe_in_file(cpe)

    def _get_cve_matches(self, cpe: CPERecord):
        cve_collection = self.database['cvedetails']
        return cve_collection.find(cpe.get_query_str())
