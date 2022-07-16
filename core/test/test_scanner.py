from core.scanner.scan_invoker import Scan_Invoker
from core.scanner.software import Software
from core.scanner.hardware import Hardware
import unittest


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.software_list = []
        self.hardware_list = []
        self.invoker = Scan_Invoker()

    def test_software_package_installed(self):
        """ Scenario : Check that scanner find installed package 
            Given : apt package installed """
        """ When : Scanner is scan software installed """
        self.invoker.set_on_start(Software())
        self.software_list = self.invoker.invoke()
        """ Then : Scanner find apt package and add him to the list """
        flag = False 
        for record in self.software_list:
            if record["product"] == "apt":
                flag = True
        self.assertTrue(flag)

    def test_software_package_not_installed(self):
        """ Scenario : Check that scanner dont find package that is not installed  
            Given : photoshop package is not installed """
        """ When : Scanner is scan software installed """
        self.invoker.set_on_start(Software())
        self.software_list = self.invoker.invoke()
        """ Then : Scanner do not find photoshop package """
        flag = True
        for record in self.software_list:
            if record["product"] == "photoshop":
                flag = False
        self.assertTrue(flag)

    def test_hardware_exists(self):
        """ Scenario : Check that scanner find exists hardware 
            Given : VMware Virtual Platform hardware exists """
        """ When : Scanner is scan hardware """
        self.invoker.set_on_start(Hardware())
        self.hardware_list = self.invoker.invoke()
        """ Then : Scanner find VMware Virtual Platform hardware and add him to the list """
        flag = False 
        for record in self.hardware_list:
            if record["product"] == " VMware Virtual Platform":
                flag = True
        self.assertTrue(flag)       

    def test_hardware_not_exists(self):
        """ Scenario : Check that scanner dont find hardware that is not exists  
            Given : amd hardware is not exist """
        """ When : Scanner is scan hardware """
        self.invoker.set_on_start(Hardware())
        self.hardware_list = self.invoker.invoke()
        """ Then : Scanner do not find amd package """
        flag = True
        for record in self.hardware_list:
            if record["product"] == "amd":
                flag = False
        self.assertTrue(flag)