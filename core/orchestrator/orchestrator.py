import logging
import copy
from multiprocessing import connection
from core.obj.cpe_record import CPERecord
from core.obj.cve_record import CVERecord
from core.utils import *
from core.scanner.scan_invoker import Scan_Invoker
from core.scanner.software import Software
from core.scanner.hardware import Hardware
from core.parser.parser import Parser
from core.matcher.mongo_matcher import MongoMatcher
from core.analyser.analyser import Analyser
from core.db.db_utils import get_local_db, get_remote_db
from core.mitigator.mitigator import Mitigator
from core.authenticator.authenticator import Authenticator
from core.analyser.rules_generator import generate_rules

logger = logging.getLogger("veach")
class Orchetrator:

    def __init__(self):
        self.username = None
        self.password = None
        self.is_stopped = False
        self.is_scanning = False
        self.is_matched = False
        self.software_list = []
        self.hardware_list = []
        self.invoker = Scan_Invoker()
        self.parser = Parser()
        self.db = get_local_db()[0]
        generate_rules()
        # temp because no mongodb installed on this machine
        # self.db = get_remote_db()[0]
        self.cpe_collection = get_settings_value(
            "COLLECTIONS", "cpe_collection_name")
        self.cve_collection = get_settings_value(
            "COLLECTIONS", "cve_collection_name")
        self.matcher = MongoMatcher(
            self.db, self.cpe_collection, self.cve_collection)
        self.analyser = Analyser()

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def _invoke_authenticator(self, username, password):
        self.username = username
        self.password = password
        logger.info(f"[AUTHENTICATOR] Module start")
        auth = Authenticator(username, password)
        logger.info(f"[AUTHENTICATOR] Module finish")
        if auth.authenticated:
            return True
        else:
            return False

    def invoke_scanner(self):
        """ This method will invoke software/hardware scanning and store the result in self.hardware_list & self.software_list """
        logger.info(f"[SCANNER] Module start")
        if self._invoke_authenticator(self.username, self.password):
            if get_settings_value("SCANNER", "software"):
                self.invoker.set_on_start(Software())
                self.software_list = self.invoker.invoke()

            if get_settings_value("SCANNER", "hardware"):
                self.invoker.set_on_start(Hardware())
                self.hardware_list = self.invoker.invoke()

            logger.info(f"[SCANNER] Module finish")
            return self._invoke_parser()
        else:
            raise Exception("sudo authentication failed")

    def _invoke_parser(self):
        """ This method will invoke parser to parse data in self.hardware_list & self.software_list to cpe format """
        logger.info(f"[PARSER] Moudle start")
        if self.software_list is not None:
            cpe_list = self.parser.parse_data_to_cpe(self.software_list)

        if self.hardware_list is not None:
            cpe_list.update(self.parser.parse_data_to_cpe(self.hardware_list))
        logger.info(f"[PARSER] Module finish")
        return cpe_list

    def invoke_matcher(self, cpe_list):
        """ This method will invoke matcher to find cpe and cve match in the db"""
        logger.info(f"[MATCHER] Module start")
        matches_record: set[CVERecord] = set()
        for cpe_uri in cpe_list:
            if not self.is_stopped:
                matches = self.matcher.match(cpe_uri.lower())
                if matches:
                    for key in matches.keys():
                        matches_record.update(matches[key])
                        self._invoke_analyser(matches[key])
        logger.info(f"[MATCHER] Module finish")
        return list(matches_record)

    def _invoke_analyser(self, records):
        """ This method will analyse .... """
        logger.info(f"[ANALYSER] Module start")
        cve_category = self.analyser.analyse(records)
        logger.info(f"[ANALYSER] Module finish")
        return cve_category

    def invoke_mitigator(self, cpe):
        """ This method will search mitigation for packages installed """
        logger.info(f"[MITIGATOR] Module start")
        mitigator = Mitigator(self.parser)
        output = mitigator.mitigate_package(CPERecord(cpe))
        if output:
            for categories in output.values():
                for category in categories:
                    category.affected_records = list(category.affected_records)
        logger.info(f"[MITIGATOR] Module finish")
        return output

    def get_cve_collection_info(self):
        return self.matcher.get_cve_collection_info()

    def get_cve_categories(self):
        categories = copy.deepcopy(self.analyser.cve_categories)
        for val in categories.values():
            val.affected_records = list(val.affected_records)
        return categories
