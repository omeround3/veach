from enum import Enum


class Attributes(str, Enum):
    VERSION_START_EXCLUDING = "versionStartExcluding"
    VERSION_END_INCLUDING = "versionEndIncluding"
    VERSION_START_INCLUDING = "versionStartIncluding"
    VERSION_END_EXCLUDING = "versionEndExcluding"
    VULNERABLE = "vulnerable"
    CPE_NAME = "cpe_name"
    CPE_23_URI = "cpe23Uri"


class Operators(Enum):
    AND = "AND"
    OR = "OR"
