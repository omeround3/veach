from core.db.db_utils import get_local_db, get_remote_db
import unittest


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.remote_client = ""
        self.local_client = ""

    def test_local_db_connections(self):
        """ Scenario : Check local MongoDB connections
            Given : Local MongoDB is installed on the host """
        """ When : Connection is available"""
        """ Then : Connection to DB is successfull """
        self.local_client = get_local_db()[1]
        # self.assertTrue(local_client)