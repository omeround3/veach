from enum import Enum


class CPE_Format(str, Enum):
    PART = "part"
    VENDOR = "vendor"
    PRODUCT = "product"
    VERSION = "version"


class CPE_Part(str, Enum):
    SOFTWARE = "a"
    HARDWARE = "h"
    OS = "o"
