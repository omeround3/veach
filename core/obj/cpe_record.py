import json
from typing import Dict
from core.errors import InvalidCPEStringFormat, InvalidCPEFormat
from core.matcher.enums import CPEAttributes


class CPERecord():
    def __init__(self, cpe: Dict[str, str]) -> None:
        """deserialization class for CPE record"""
        if CPEAttributes.CPE_23_URI in cpe:
            tmp = cpe[CPEAttributes.CPE_23_URI].split(':')
        else:
            raise InvalidCPEFormat(json.dumps(cpe))

        if tmp[0] != "cpe" or len(tmp) != 13:
            raise InvalidCPEStringFormat(cpe[CPEAttributes.CPE_23_URI])
        self._version_end_excluding = None
        self._version_start_excluding = None
        self._version_end_including = None
        self._version_start_including = None

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

        if CPEAttributes.VERSION_END_EXCLUDING in cpe:
            self._version_end_excluding = cpe[CPEAttributes.VERSION_END_EXCLUDING]

        if CPEAttributes.VERSION_START_EXCLUDING in cpe:
            self._version_start_excluding = cpe[CPEAttributes.VERSION_START_EXCLUDING]

        if CPEAttributes.VERSION_END_INCLUDING in cpe:
            self._version_end_including = cpe[CPEAttributes.VERSION_END_INCLUDING]

        if CPEAttributes.VERSION_START_INCLUDING in cpe:
            self._version_start_including = cpe[CPEAttributes.VERSION_START_INCLUDING]

    def __str__(self) -> str:
        return f"cpe:{self._cpe_version}:{self._part}:{self._vendor}:{self._product}:{self._version}:{self._update}:{self._edition}:{self._language}:{self._sw_edition}:{self._target_sw}:{self._target_hw}:{self._other}"

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
