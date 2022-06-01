from core.obj.cpe_record import CPERecord
from core.matcher.enums import Attributes
import json


class FakeCPE():
    def __init__(self, file) -> None:
        tmp = open(file, encoding='utf-8')
        data = json.load(tmp)
        data = data["matches"]
        self.data = data

    def _find_cpe_in_file(self, cpe_str: str):
        res = []
        for cpe in self.data:
            for name in cpe['cpe_name']:
                if name[Attributes.CPE_23_URI] == cpe_str:
                    res.append(CPERecord(cpe))
        return res
