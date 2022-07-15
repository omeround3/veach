from core.authenticator.authenticator import Authenticator
import unittest


class TestParser(unittest.TestCase):
    def setUp(self):
        pass

    def valid_username_and_password(self):
        """ Scenario : check if user is part of sudo group 
            Given : valid user name and password """
        """ When : authentication check """
        username = ""
        password = ""
        """ Then : authenticator return true"""
        auth = Authenticator(username, password)
        self.assertTrue(auth.authenticated)

    def non_valid_username_password(self):
        """ Scenario : check if  user is part of the sudo group 
            Given : Non valid user name and password """
        """ When : authentication check """
        username = ""
        password = ""
        """ Then : authenticator return false"""
        auth = Authenticator(username, password)
        self.assertFlase(auth.authenticated)