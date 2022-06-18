from collections import defaultdict
from enum import Enum
from ntpath import join

from core.analyser.enums import BaseMetricAttributes


class Version(Enum):
    V3_1 = '3.1'
    V3_0 = '3.0'


class AttackVector(Enum):
    ADJACENT_NETWORK = 'ADJACENT_NETWORK'
    NETWORK = 'NETWORK'
    LOCAL = 'LOCAL'
    PHYSICAL = 'PHYSICAL'


class AttackComplexity(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'


class PrivilegesRequired(Enum):
    HIGH = 'HIGH'
    NONE = 'NONE'
    LOW = 'LOW'


class UserInteraction(Enum):
    NONE = 'NONE'
    REQUIRED = 'REQUIRED'


class Scope(Enum):
    UNCHANGED = 'UNCHANGED'
    CHANGED = 'CHANGED'


class ConfidentialityImpact(Enum):
    HIGH = 'HIGH'
    NONE = 'NONE'
    LOW = 'LOW'


class IntegrityImpact(Enum):
    HIGH = 'HIGH'
    NONE = 'NONE'
    LOW = 'LOW'


class AvailabilityImpact(Enum):
    HIGH = 'HIGH'
    NONE = 'NONE'
    LOW = 'LOW'


class CVSSRecordV3():
    type = BaseMetricAttributes.V3

    def __init__(self, vector_string: str):
        # validate string using regex
        """deserialization class for cvssV3 record"""
        self.vector_string_attributes: dict = defaultdict(lambda: str())
        self.vector_string = vector_string

        for attr in self.vector_string.split("/"):
            tmp = attr.split(":")
            self.vector_string_attributes[tmp[0]] = tmp[1]

    def __hash__(self) -> int:
        return self.vector_string.__hash__()

    def __eq__(self, __o: object) -> bool:
        return self.vector_string == __o.vector_string

    def __str__(self) -> str:
        return self.vector_string
