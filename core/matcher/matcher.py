from collections import defaultdict
import configparser
from gc import collect
from msilib.schema import Error

from core.errors import MissingConfigFileOption, MissingConfigFileSection
from core.matcher.enums import CPEAttributes
from ..obj.cve_record import CVERecord
from ..obj.cpe_record import CPERecord
from pymongo import database


class Matcher:
    """Abstract class for matching CPE URI to CVE records"""

    def __init__(self, database: database.Database = None) -> None:
        self._database = database
        self.matches: dict[str, set[CVERecord]] = defaultdict(lambda: set())

    def match(self, cpe: str):
        pass
