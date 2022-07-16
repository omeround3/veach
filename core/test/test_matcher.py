from core.matcher.mongo_matcher import MongoMatcher
from core.db.db_utils import get_local_db
from core.utils import *
import unittest


class TestMatcher(unittest.TestCase):
    def setUp(self):
        self.db = get_local_db()[0]
        # temp because no mongodb installed on this machine
        # self.db = get_remote_db()[0]
        self.cpe_collection = get_settings_value(
            "COLLECTIONS", "cpe_collection_name")
        self.cve_collection = get_settings_value(
            "COLLECTIONS", "cve_collection_name")
        self.matcher = MongoMatcher(
            self.db, self.cpe_collection, self.cve_collection)

    def test_cpe_match_exist(self):
        matches = self.matcher.match(
            "cpe:2.3:a:10-strike:network_monitor:5.4:*:*:*:*:*:*:*")
        self.assertTrue(len(matches) > 0)

    def test_cpe_match_not_exist(self):
        matches = self.matcher.match(
            "cpe:2.3:a:10-strike:this_cpe_does_not_exist:5.4:*:*:*:*:*:*:*")
        self.assertTrue(len(matches) == 0)
