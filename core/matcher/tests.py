from core.matcher.mongo_matcher import MongoMatcher
import unittest
import pymongo


class TestMatcher(unittest.TestCase):
    def setUp(self):
        client = pymongo.MongoClient(
            "mongodb+srv://veach:gfFVGjpGfeayd3Qe@cluster0.gnukl.mongodb.net/?authMechanism=DEFAULT")
        db = client['nvdcve']
        self.matcher = MongoMatcher(db)

    def test_cpe_match_exist(self):
        self.matcher.match(
            "cpe:2.3:a:10-strike:network_monitor:5.4:*:*:*:*:*:*:*")
        self.assertTrue(len(self.matcher.matches) > 0)

    def test_cpe_match_not_exist(self):
        self.matcher.match(
            "cpe:2.3:a:10-strike:this_cpe_does_not_exist:5.4:*:*:*:*:*:*:*")
        self.assertTrue(len(self.matcher.matches) == 0)
