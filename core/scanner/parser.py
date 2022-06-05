from enums import CPE_Format, CPE_Part


class Parser:
    """
    Parser responsible for getting different scanner data and to parse him in a cpe formant
    e.g. cpe:2.3:a:vendor:product:version:*:*:*:*:*
    """

    def __init__(self):
        self.cpe_list = []

    def parse_string(self, tmp: str) -> str:
        tmp = tmp.replace(",", "")
        tmp = tmp.replace(" ", "_")
        tmp = tmp.replace("/", "_")
        return tmp


    def parse_vendor(self, cpe: {}, cpe_str: str) -> str:
        """
        parse vendor to cpe format
        :param cpe:
        :param cpe_str:
        :return:
        """
        if cpe[CPE_Format.VENDOR] is None:
            cpe_str += "*:"
        else:
            vendor = self.parse_string(cpe[CPE_Format.VENDOR].strip())
            cpe_str += vendor + ":"
        return cpe_str

    def parse_product(self, cpe: {}, cpe_str: str) -> str:
        """

        :param cpe:
        :param cpe_str:
        :return:
        """
        if cpe[CPE_Format.PRODUCT] is None:
            cpe_str += "*:"
        else:
            product = self.parse_string(cpe[CPE_Format.PRODUCT].strip())
            cpe_str += product + ":"
        return cpe_str

    def parse_version(self, cpe: {}, cpe_str: str) -> str:
        """

        :param cpe:
        :param cpe_str:
        :return:
        """
        if cpe[CPE_Format.VERSION] is None or cpe[CPE_Format.VERSION] == "None":
            cpe_str += "*:"
        else:
            version = self.parse_string(cpe[CPE_Format.VERSION].strip())
            cpe_str += version + ":"
        return cpe_str

    def parse_data_to_cpe(self, data: []) -> []:
        """
        :param data:
        array of dictionaries in the following structure : {"part": "", vendor": "", "product": "", "version": ""}
        :return: array of cpe
        """
        for cpe in data:
            cpe_str = "cpe:2.3:"
            if cpe[CPE_Format.PART] == CPE_Part.SOFTWARE:
                cpe_str += cpe[CPE_Format.PART].strip() + ":"
            else:
                cpe_str += cpe[CPE_Format.PART].strip() + ":"
            cpe_str = self.parse_vendor(cpe, cpe_str)
            cpe_str = self.parse_product(cpe, cpe_str)
            cpe_str = self.parse_version(cpe, cpe_str)
            cpe_str += "*:*:*:*:*"
            self.cpe_list.append(cpe_str)
        return self.cpe_list


