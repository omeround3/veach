from core.parser.parser import Parser
import unittest


class TestParser(unittest.TestCase):
    def setUp(self):
        self.parser = Parser()

    def test_parse_data(self):
        """ Scenario : Check that parser parse list to cpe format
            Given : list in the following pattren : {'part :'', 'vendor': '', 'product': '' , 'version': '' }  """
        """ When : Parser parse the list """
        record = [{'part': 'a', 'vendor': None, 'product': 'apt', 'version': '1.6.14'}]
        """ Then : parser return the data in cpe format"""
        self.assertEqual(self.parser.parse_data_to_cpe(record).pop(),'cpe:2.3:a:*:apt:1.6.14:*:*:*:*:*:*:*')

