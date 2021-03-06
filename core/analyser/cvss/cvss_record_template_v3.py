from collections import defaultdict
from enum import Enum, IntEnum

from core.analyser.enums import BaseMetricAttributes


class Version(Enum):
    V3_1 = '3.1'
    V3_0 = '3.0'


class AttackVector(str, Enum):
    ADJACENT_NETWORK = 'ADJACENT_NETWORK'
    NETWORK = 'NETWORK'
    LOCAL = 'LOCAL'
    PHYSICAL = 'PHYSICAL'


class AttackComplexity(str, Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'


class PrivilegesRequired(str, Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'
    NONE = 'NONE'


class UserInteraction(str, Enum):
    REQUIRED = 'REQUIRED'
    NONE = 'NONE'


class Scope(str, Enum):
    UNCHANGED = 'UNCHANGED'
    CHANGED = 'CHANGED'


class ConfidentialityImpact(str, Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    HIGH = 'HIGH'


class IntegrityImpact(str, Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    HIGH = 'HIGH'


class AvailabilityImpact(str, Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    HIGH = 'HIGH'


class Values(IntEnum):
    N = 1
    L = 2
    H = 3

    R = 4

    U = 5
    C = 6


class CVSSRecordV3():
    type = BaseMetricAttributes.V3

    def __init__(self, vector_string: str):
        if not isinstance(vector_string, str):
            vector_string = str(vector_string)
        # validate string using regex
        """deserialization class for cvssV3 record"""
        self.vector_string_attributes: dict = defaultdict(str)
        self.vector_string = vector_string

        for attr in self.vector_string.split("/"):
            tmp = attr.split(":")
            self.vector_string_attributes[tmp[0]] = tmp[1]

    def meets(self, rule: BaseMetricAttributes) -> bool:
        """
        Checks if Category meets Rule conditions: 
        e.g - Rule(AC.HIGH) = I want to know about vulnerabilities 
        that are complex to perform (attack complexity = HIGH),
        will meet all Categories with AC.HIGH or(!) AC.LOW
        (because they are easier to perform)
        """
        if not rule.vector_string_attributes:
            return False

        for key in rule.vector_string_attributes.keys():
            rule_val = rule.vector_string_attributes[key]
            self_val = self.vector_string_attributes[key]
            if key == "AV":
                if self_val != rule_val:
                    return False
            elif key == "AC" or key == "PR" or key == "UI":
                if Values[self_val] > Values[rule_val]:
                    return False
            else:
                if Values[self_val] < Values[rule_val]:
                    return False
        return True

    def __hash__(self) -> int:
        return self.vector_string.__hash__()

    def __eq__(self, __o: object) -> bool:
        return self.vector_string == __o.vector_string

    def __str__(self) -> str:
        return self.vector_string
