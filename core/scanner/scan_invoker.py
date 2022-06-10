from core.scanner.scanner import Scanner

class Scan_Invoker:

    def __init__(self):
        """ The Scan Invoker send a request to execute scan components """
        self.start = None

    def set_on_start(self, scanner: Scanner):
        """
        :param scanner: One of scanner children e.g. software, hardware
        """
        self.start = scanner

    def invoke(self) -> list:
        """
        Execute scanning components
        :return: List of dictionaries in the following structure : {"vendor": "", "product": "", "version" : ""}
        """
        if isinstance(self.start, Scanner):
            return self.start.execute()

