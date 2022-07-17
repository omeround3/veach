from collections import defaultdict

from ..obj.cve_record import CVERecord
from pymongo import database


class Matcher:
    """Abstract class for matching CPE URI to CVE records"""

    def __init__(self, database: database.Database = None) -> None:
        self._database = database
        self.matches: dict[str, set[CVERecord]] = defaultdict(set)

    def match(self, cpe_uri: str):
        pass
