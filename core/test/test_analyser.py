from core.analyser.analyser import Analyser
from core.matcher.mongo_matcher import MongoMatcher
from core.db.db_utils import get_local_db
from core.utils import *
from core.obj.cve_record import CVERecord
import unittest


class TestAnalyser(unittest.TestCase):
    def setUp(self) -> None:
        self.db = get_local_db()[0]
        # temp because no mongodb installed on this machine
        # self.db = get_remote_db()[0]
        self.cpe_collection = get_settings_value(
            "COLLECTIONS", "cpe_collection_name")
        self.cve_collection = get_settings_value(
            "COLLECTIONS", "cve_collection_name")
        self.matcher = MongoMatcher(
            self.db, self.cpe_collection, self.cve_collection)
        self.analyser = Analyser()
        
    
    def test_analyser(self):
        """ Scenario : CVE found and sent to analyser 
            Given : CPE send to matcher """
        """ When : analyser.analyse run """
        """ Then : analyser return list of category"""
        matches_record: set[CVERecord] = set()
        matches = self.matcher.match('cpe:2.3:a:*:accountsservice:0.6.45-ubuntu1.3:*:*:*:*:*:*:*')
        if matches:
            for key in matches.keys():
                matches_record.update(matches[key])        
                cve_category = self.analyser.analyse(matches[key])
            self.assertTrue(len(cve_category) > 0)
