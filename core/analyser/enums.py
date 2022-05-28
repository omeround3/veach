from enum import IntEnum,Enum, auto


class Severity(IntEnum):
    LOW = 0
    LOW_MEDIUM = 1
    MEDIUM = 2
    MEDIUM_HIGH = 3
    HIGH = 4


class CVSS(Enum):
    """An enum class for Common Vulnerability Scoring System (CVSS) options"""
    V2 = "baseMetricV2"
    V3 = "baseMetricV3"
