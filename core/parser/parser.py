from core.scanner.enums import CPEFormat, CPEPart


class Parser:
    """ Parser responsible for getting different scanner data and parse him to a cpe format
    e.g. cpe:2.3:a:vendor:product:version:*:*:*:*:*
    """

    def __init__(self):
       pass

    def _parse_string(self, tmp: str) -> str:
        tmp = tmp.replace(",", "")
        tmp = tmp.replace(" ", "_")
        tmp = tmp.replace("/", "_")
        tmp = tmp.replace(":","&colon")
        return tmp


    def _parse_vendor(self, cpe: dict, cpe_str: str) -> str:
        """ Parse vendor to CPE format
        :param cpe: Dictionary with CPE data
        :param cpe_str: String in CPE format
        :return: cpe_str after parsing
        """
        if cpe[CPEFormat.VENDOR] is None:
            cpe_str += "*:"
        else:
            vendor = self._parse_string(cpe[CPEFormat.VENDOR].strip())
            cpe_str += vendor + ":"
        return cpe_str

    def _parse_product(self, cpe: dict, cpe_str: str) -> str:
        """ Parse product to CPE format
        :param cpe: Dictionary with CPE data 
        :param cpe_str: String in CPE format
        :return: cpe_str after parsing 
        """
        if cpe[CPEFormat.PRODUCT] is None:
            cpe_str += "*:"
        else:
            product = self._parse_string(cpe[CPEFormat.PRODUCT].strip())
            cpe_str += product + ":"
        return cpe_str

    def _parse_version(self, cpe: dict, cpe_str: str) -> str:
        """ Parse version to CPE format
        :param cpe: Dictionary with CPE data
        :param cpe_str: String in CPE format
        :return: cpe_str after parsing
        """
        if cpe[CPEFormat.VERSION] is None or cpe[CPEFormat.VERSION] == "None":
            cpe_str += "*:"
        else:
            version = self._parse_string(cpe[CPEFormat.VERSION].strip())
            cpe_str += version + ":"
        return cpe_str

    def parse_data_to_cpe(self, data: list):
        """
        Take list of data and parse him to CPE format
        :param data: List of dictionaries in the following structure : {"part": "", vendor": "", "product": "", "version": ""}
        :return: List of CPE
        """
        cpe_list = set()
        for cpe in data:
            cpe_str = "cpe:2.3:"
            if cpe[CPEFormat.PART] == CPEPart.SOFTWARE:
                cpe_str += cpe[CPEFormat.PART].strip() + ":"
            else:
                cpe_str += cpe[CPEFormat.PART].strip() + ":"
            cpe_str = self._parse_vendor(cpe, cpe_str)
            cpe_str = self._parse_product(cpe, cpe_str)
            cpe_str = self._parse_version(cpe, cpe_str)
            cpe_str += "*:*:*:*:*:*:*" 
            cpe_list.add(cpe_str)
        return cpe_list
        


