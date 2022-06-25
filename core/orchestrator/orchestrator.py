import utils
import pymongo
from core.scanner.scan_invoker import Scan_Invoker
from core.scanner.software import Software
from core.scanner.hardware import Hardware
from core.parser.parser import Parser
from core.matcher.matcher import Matcher
from core.matcher.mongo_matcher import MongoMatcher
from core.analyser.analyser import Analyser


class Orchetrator:
    
    def __init__(self):
        self.software_list = []
        self.hardware_list = []
        self.cpe_list = []
        self.matches = []

    def invoke_scanner(self):
        """ This method will invoke software/hardware scanning and pass the result to parser component """

        invoker = Scan_Invoker()
        if utils.get_settings_value("SCANNER","software") :
            invoker.set_on_start(Software())
            self.software_list = invoker.invoke()
     
        elif utils.get_settings_value("SCANNER","hardware") :
            invoker.set_on_start(Hardware())
            self.hardware_list = invoker.invoke()
           
        
        self.invoke_parser()
        
    def invoke_parser(self):
        """ This method will invoke parser to parse data to cpe format """
        parser = Parser()
        if self.software_list is not None:
             self.cpe_list = parser.parse_data_to_cpe(self.software_list)

        if self.hardware_list is not None:
            self.cpe_list += parser.parse_data_to_cpe(self.hardware_list)

        self.invoke_matcher()
        print(len(self.cpe_list))


    def invoke_matcher(self):
        client = pymongo.MongoClient("mongodb+srv://veach:gfFVGjpGfeayd3Qe@cluster0.gnukl.mongodb.net/?authMechanism=DEFAULT")
        db = client['nvdcve']

        matcher: Matcher = MongoMatcher(db)

        for cpe_uri in self.cpe_list:
             matcher.match(cpe_uri[0].lower())
        
        self.matches = matcher.matches
        self.invoke_analyser()
        

        

    def invoke_analyser(self):

        analyser = Analyser()
        if self.matches:
            for match in self.matches.keys():
                analyser.add(self.matches[match])
            analyser.analyse()

        
    

