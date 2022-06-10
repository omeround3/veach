from enum import Enum


class CPEFormat(str, Enum):
    "An enum class for the CPE format "
    PART = "part"
    VENDOR = "vendor"
    PRODUCT = "product"
    VERSION = "version"


class CPEPart(str, Enum):
    "An enum class for the CPE part options"
    SOFTWARE = "a"
    HARDWARE = "h"
    OS = "o"
