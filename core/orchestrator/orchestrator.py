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
        self.cpe_collection = get_settings_value("MATCHER", "cpe_collection_name")
        self.cve_collection = get_settings_value("MATCHER", "cve_collection_name")
        self.matcher = MongoMatcher(db,self.cpe_collection,self.cve_collection)
        self.analyser = Analyser()

    def invoke_scanner(self):
        """ This method will invoke software/hardware scanning and pass the result to parser component """
        
        if get_settings_value("SCANNER","software"):
            self.invoker.set_on_start(Software())
            self.software_list = self.invoker.invoke()
     
        if get_settings_value("SCANNER","hardware") :
            self.invoker.set_on_start(Hardware())
            self.hardware_list = self.invoker.invoke()
            
        print("Step 1 : Scanner is Done\n")
        self.invoke_parser()
        
    def invoke_parser(self):
        """ This method will invoke parser to parse data to cpe format """
       
        if self.software_list is not None:
             self.cpe_list = self.parser.parse_data_to_cpe(self.software_list)

        if self.hardware_list is not None:
             self.cpe_list.update(self.parser.parse_data_to_cpe(self.hardware_list))
        print("Step 2 : Parser is Done\n")
        self.invoke_matcher()

    def invoke_matcher(self):
        """ This method will invoke matcher to find cpe and cve match in the db"""
        counter = 0 
        for cpe_uri in self.cpe_list:
            found = self.matcher.match(cpe_uri.lower())
            #print(found)
            counter += 1
        print(counter, end=": ")
        if self.matcher.matches:
            for key in self.matcher.matches.keys():
                self.analyser.add(self.matcher.matches[key])
        print("Step 3 : Matcher is Done\n")
        self.invoke_analyser()
        

    def invoke_analyser(self):
        """ This method will analyse .... """

        self.analyser.analyse()
        for key in self.analyser.cve_categories.keys():
            category = self.analyser.cve_categories[key]
            print(category.tag)
            if category.affected_records:
                for cve in category.affected_records:
                    print(" "+str(cve._id))
            else:
                print(" None")
        print("Step 4 : Analyser is Done")

        
    def invoke_mitigator(self):
        pass 
        #add here the function 

