from enum import Enum


class CVEAttributes(str, Enum):
    """An enum class for CVE fields"""
    ID = "cve.CVE_data_meta.ID"
    NODES = "configurations.nodes"
    CVSSV2 = "impact.baseMetricV2.cvssV2"
    CVSSV3 = "impact.baseMetricV3.cvssV3"
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
    ID = "_id"


class Operators(Enum):
    """An enum class for node opertaor field"""
    AND = "AND"
    OR = "OR"
