from enum import Enum


class CVEAttributes(str, Enum):
    """An enum class for CVE fields"""
    CVE = "cve"
    CONFIGURATION = "configurations"
    IMPACT = "impact"
    PUBLISHED_DATE = "publishedDate"
    LAST_MODIFIED_DATE = "lastModifiedDate"


class CPEAttributes(str, Enum):
    """An enum class for CPE match fields"""
    VERSION_START_EXCLUDING = "versionStartExcluding"
    VERSION_END_INCLUDING = "versionEndIncluding"
    VERSION_START_INCLUDING = "versionStartIncluding"
    VERSION_END_EXCLUDING = "versionEndExcluding"
    VULNERABLE = "vulnerable"
    CPE_NAME = "cpe_name"
    CPE_23_URI = "cpe23Uri"


class Operators(Enum):
    """An enum class for node opertaor field"""
    AND = "AND"
    OR = "OR"
