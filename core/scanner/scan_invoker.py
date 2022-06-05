from scanner import Scanner

class Scan_Invoker:

    def __init__(self):
        """
        The Scan Invoker send a request to execute component scan
        """
        self.start = None

    def set_on_start(self, scanner: Scanner):
        """
        :param scanner: one of scanner children e.g. software, hardware
        """
        self.start = scanner

    def invoke(self) -> []:
        """
        execute scanning components
        :return:
        array of dictionaries in the following structure : {"vendor": "", "product": "", "version" : ""}
        """
        if isinstance(self.start, Scanner):
            return self.start.execute()

