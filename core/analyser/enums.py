from enum import IntEnum, Enum, auto


class Severity(IntEnum):
    """An enum class for the weighting the severity of CVEs"""
    LOW = 0
    LOW_MEDIUM = 1
    MEDIUM = 2
    MEDIUM_HIGH = 3
    HIGH = 4


class BaseMetricAttributes(str, Enum):
    """An enum class for Common Vulnerability Scoring System (CVSS) options"""
    V2 = "baseMetricV2"
    V3 = "baseMetricV3"


class CVSSV3Attributes(str, Enum):
    """An enum class for Common Vulnerability Scoring System (CVSS) options"""
    BASE_SCORE = "cvssV3.baseScore"
    VECTOR_STRING = "cvssV3.vectorString"
