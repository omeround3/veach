from core.utils import * 
import pymongo
from core.scanner.scan_invoker import Scan_Invoker
from core.scanner.software import Software
from core.scanner.hardware import Hardware
from core.parser.parser import Parser
from core.matcher.mongo_matcher import MongoMatcher
from core.analyser.analyser import Analyser


class Orchetrator:
    
    def __init__(self):
        self.software_list = []
        self.hardware_list = []
        self.cpe_list = set()
        self.matches = []
        self.invoker = Scan_Invoker()
        self.parser = Parser()
        self.client = pymongo.MongoClient(get_settings_value("MATCHER","db_client"))
        db = self.client[get_settings_value("MATCHER","db_name")]
        self.matcher = MongoMatcher(db)

    def invoke_scanner(self):
        """ This method will invoke software/hardware scanning and pass the result to parser component """
        
        if get_settings_value("SCANNER","software"):
            self.invoker.set_on_start(Software())
            self.software_list = self.invoker.invoke()
     
        if get_settings_value("SCANNER","hardware") :
            self.invoker.set_on_start(Hardware())
            self.hardware_list = self.invoker.invoke()
            
        
        self.invoke_parser()
        
    def invoke_parser(self):
        """ This method will invoke parser to parse data to cpe format """
       
        if self.software_list is not None:
             self.cpe_list = self.parser.parse_data_to_cpe(self.software_list)

        if self.hardware_list is not None:
             self.cpe_list.update(self.parser.parse_data_to_cpe(self.hardware_list))
        
        self.invoke_matcher()

    def invoke_matcher(self):
        """ This method will invoke matcher to find cpe and cve match in the db"""
        for cpe_uri in self.cpe_list:
             self.matcher.match(cpe_uri[0].lower())
        
        self.matches = self.matcher.matches
        self.invoke_analyser()
        

    def invoke_analyser(self):
        """ This method will analyse .... """
        analyser = Analyser()
        if self.matches:
            for match in self.matches.keys():
                analyser.add(self.matches[match])
            analyser.analyse()

        
    def invoke_mitigator(self):
        pass 
        #add here the function 

