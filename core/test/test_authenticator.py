from core.authenticator.authenticator import Authenticator
import unittest


class TestParser(unittest.TestCase):

    def test_valid_username_and_password(self):
        """ Scenario : check if user is part of sudo group 
            Given : valid user name and password """
        """ When : authentication check """
        username = "user"
        password = "Password1"
        """ Then : authenticator return true"""
        self.assertTrue(Authenticator(username, password).authenticated)

    def test_non_valid_username_password(self):
        """ Scenario : check if  user is part of the sudo group 
            Given : Non valid user name and password """
        """ When : authentication check """
        username = "user1"
        password = "Password2"
        """ Then : authenticator return false"""
        self.assertFalse(Authenticator(username, password).authenticated)