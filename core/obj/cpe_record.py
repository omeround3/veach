from typing import Dict

from core.matcher.enums import CPEAttributes
from core.utils import get_attribute


class CPERecord():
    def __init__(self, cpe: Dict[str, str]) -> None:
        """deserialization class for CPE record"""
        cpe_uri: str = get_attribute(cpe, CPEAttributes.CPE_23_URI)
        self.cpe_uri = cpe_uri

        # replace literal colons
        if CPERecord.is_valid(cpe_uri):
            cpe_uri = cpe_uri.replace("\:", "&colon;")
            cpe_uri = cpe_uri.split(":")
            for part in cpe_uri:
                part.replace("&colon;", ":")

            self._generated_id = get_attribute(cpe, CPEAttributes.ID)
            self._cpe_version = cpe_uri[1]
            self._part = cpe_uri[2]
            self._vendor = cpe_uri[3]
            self._product = cpe_uri[4]
            self._version = cpe_uri[5]
            self._update = cpe_uri[6]
            self._edition = cpe_uri[7]
            self._language = cpe_uri[8]
            self._sw_edition = cpe_uri[9]
            self._target_sw = cpe_uri[10]
            self._target_hw = cpe_uri[11]
            self._other = cpe_uri[12]

            self._version_end_excluding = get_attribute(
                cpe, CPEAttributes.VERSION_END_EXCLUDING)
            self._version_start_excluding = get_attribute(
                cpe, CPEAttributes.VERSION_START_EXCLUDING)
            self._version_end_including = get_attribute(
                cpe, CPEAttributes.VERSION_END_INCLUDING)
            self._version_start_including = get_attribute(
                cpe, CPEAttributes.VERSION_START_INCLUDING)

    def __str__(self) -> str:
        return self.cpe_uri

    def __hash__(self) -> int:
        return str(self).__hash__()

    def __eq__(self, __o: object) -> bool:
        return self._version_end_excluding == __o._version_end_excluding and \
            self._version_start_excluding == __o._version_start_excluding and\
            self._version_end_including == __o._version_end_including and \
            self._version_start_including == __o._version_start_including and \
            self._cpe_version == __o._cpe_version and \
            self._part == __o._part and \
            self._vendor == __o._vendor and \
            self._product == __o._product and \
            self._version == __o._version and \
            self._update == __o._update and \
            self._edition == __o._edition and \
            self._language == __o._language and \
            self._sw_edition == __o._sw_edition and \
            self._target_sw == __o._target_sw and \
            self._target_hw == __o._target_hw and \
            self._other == __o._other

    def is_valid(cpe_uri: str) -> bool:
        if cpe_uri:
            tmp = cpe_uri.replace("\:", "&colon;")
            tmp = tmp.split(":")
            if tmp[0] == "cpe" and len(tmp) == 13:
                return True
            else:
                return False
