import json
from core.errors import InvalidCPEStringFormat, InvalidCPEFormat
from core.matcher.enums import Attributes


class CPERecord:
    def __init__(self, cpe: dict) -> None:
        if Attributes.CPE_23_URI in cpe:
            tmp = cpe[Attributes.CPE_23_URI].split(':')
        else:
            raise InvalidCPEFormat(json.dumps(cpe))

        if tmp[0] != "cpe" or len(tmp) != 13:
            raise InvalidCPEStringFormat(cpe[Attributes.CPE_23_URI])

        self._cpe_version = tmp[1]
        self._part = tmp[2]
        self._vendor = tmp[3]
        self._product = tmp[4]
        self._version = tmp[5]
        self._update = tmp[6]
        self._edition = tmp[7]
        self._language = tmp[8]
        self._sw_edition = tmp[9]
        self._target_sw = tmp[10]
        self._target_hw = tmp[11]
        self._other = tmp[12]

        if Attributes.VERSION_END_EXCLUDING in cpe:
            self.version_end_excluding = cpe[Attributes.VERSION_END_EXCLUDING]

        if Attributes.VERSION_START_EXCLUDING in cpe:
            self.version_start_excluding = cpe[Attributes.VERSION_START_EXCLUDING]

        if Attributes.VERSION_END_INCLUDING in cpe:
            self.version_end_including = cpe[Attributes.VERSION_END_INCLUDING]

        if Attributes.VERSION_START_INCLUDING in cpe:
            self.version_start_including = cpe[Attributes.VERSION_START_INCLUDING]
