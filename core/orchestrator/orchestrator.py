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
from core.db.db_utils import *
from core.mitigator.mitigator import Mitigator


class Orchetrator:

    def __init__(self):
        self.software_list = []
        self.hardware_list = []
        self.invoker = Scan_Invoker()
        self.parser = Parser()
        #self.db = get_local_db()[0]
        # temp because no mongodb installed on this machine
        self.db = get_remote_db()[0]
        self.cpe_collection = get_settings_value(
            "COLLECTIONS", "cpe_collection_name")
        self.cve_collection = get_settings_value(
            "COLLECTIONS", "cve_collection_name")
        self.matcher = MongoMatcher(
            self.db, self.cpe_collection, self.cve_collection)
        self.analyser = Analyser()

    def invoke_scanner(self):
        """ This method will invoke software/hardware scanning and pass the result to parser component """

        if get_settings_value("SCANNER", "software"):
            self.invoker.set_on_start(Software())
            self.software_list = self.invoker.invoke()

        if get_settings_value("SCANNER", "hardware"):
            self.invoker.set_on_start(Hardware())
            self.hardware_list = self.invoker.invoke()

        print("Step 1 : Scanner is Done\n")
        return self._invoke_parser()

    def _invoke_parser(self):
        """ This method will invoke parser to parse data to cpe format """

        if self.software_list is not None:
            cpe_list = self.parser.parse_data_to_cpe(self.software_list)

        if self.hardware_list is not None:
            cpe_list.update(self.parser.parse_data_to_cpe(self.hardware_list))
        print("Step 2 : Parser is Done\n")
        return cpe_list

    def invoke_matcher(self, cpe_list):
        """ This method will invoke matcher to find cpe and cve match in the db"""
        matches_record: set[CVERecord] = set()
        for cpe_uri in cpe_list:
            matches = self.matcher.match(cpe_uri.lower())
            if matches:
                print(matches)
                for key in matches.keys():
                    matches_record.update(matches[key])
                    self._invoke_analyser(matches[key])
        print("Step 3 : Matcher is Done\n")
        return list(matches_record)

    def _invoke_analyser(self, records):
        """ This method will analyse .... """

        cve_category = self.analyser.analyse(records)
        print("Step 4 : Analyser is Done")
        return cve_category

    def invoke_mitigator(self, cpe):
        """ This method will search mitigation for packages installed """
        mitigator = Mitigator(self.parser)
        output = mitigator.mitigate_package(CPERecord(cpe))
        if output:
            for categories in output.values():
                for category in categories:
                    category.affected_records = list(category.affected_records)
        return output

    def get_cve_collection_info(self):
        return self.matcher.get_cve_collection_info()

    def get_cve_categories(self):
        categories = copy.deepcopy(self.analyser.cve_categories)
        for val in categories.values():
            val.affected_records = list(val.affected_records)
        return categories
