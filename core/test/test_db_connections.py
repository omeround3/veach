from core.db.db_utils import get_local_db, get_remote_db
import unittest


class TestDBs(unittest.TestCase):
    def setUp(self):
        self.remote_client = None
        self.local_client = None

    def test_local_db_connections(self):
        """ 
            Scenario : Check local MongoDB connection
            Given : Local MongoDB is installed on the host
            When : Connection is available
            Then : Connection to DB is successfull 
        """
        
        self.local_client = get_local_db()[1]
        self.assertIsNotNone(self.local_client)
    
    def test_remote_db_connections(self):
        """ 
            Scenario : Check remote MongoDB connection
            Given : Remote MongoDB is installed on the host
            When : Connection is available
            Then : Connection to DB is successfull 
        """

        self.remote_client = get_remote_db()[1]
        self.assertIsNotNone(self.remote_client)