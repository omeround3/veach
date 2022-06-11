from enum import Enum
from ntpath import join


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


# class BaseSeverity(Enum):
#     MEDIUM = 'MEDIUM'
#     HIGH = 'HIGH'
#     CRITICAL = 'CRITICAL'
#     LOW = 'LOW'


class RecordTemplateV3():
    def __init__(self,
                 version: Version = None,
                 attack_vector: AttackVector = None,
                 attack_complexity: AttackComplexity = None,
                 privileges_required: PrivilegesRequired = None,
                 user_interaction: UserInteraction = None,
                 scope: Scope = None,
                 confidentiality_impact: ConfidentialityImpact = None,
                 integrity_impact: IntegrityImpact = None,
                 availability_impact: AvailabilityImpact = None,
                 ):
        """deserialization class for cvssV3 record"""
        self.vector_string_attributes = []
        if version:
            self.vector_string_attributes.append(f"CVSS:{version.value}")
        if attack_vector:
            self.vector_string_attributes.append(
                f"AV:{attack_vector.value[0]}")
        if attack_complexity:
            self.vector_string_attributes.append(
                f"AC:{attack_complexity.value[0]}")
        if privileges_required:
            self.vector_string_attributes.append(
                f"PR:{privileges_required.value[0]}")
        if user_interaction:
            self.vector_string_attributes.append(
                f"UI:{user_interaction.value[0]}")
        if scope:
            self.vector_string_attributes.append(f"S:{scope.value[0]}")
        if confidentiality_impact:
            self.vector_string_attributes.append(
                f"C:{confidentiality_impact.value[0]}")
        if integrity_impact:
            self.vector_string_attributes.append(
                f"I:{integrity_impact.value[0]}")
        if availability_impact:
            self.vector_string_attributes.append(
                f"A:{availability_impact.value[0]}")
        self.vector_string = '/'.join(str(a)
                                      for a in self.vector_string_attributes)

    def __hash__(self) -> int:
        return self.vector_string.__hash__()

    def __eq__(self, __o: object) -> bool:
        return self.vector_string == __o.vector_string

    def __str__(self) -> str:
        return self.vector_string
    #
    # def __str__(self):
    #     ret_str = str()
    #     if self.version:
    #         self.vector_string.append(f"CVSS:{self.version.value}/")
    #         ret_str += f"CVSS:{self.version.value}/"
    #     if self.attack_vector:
    #         ret_str += f"AV:{self.attack_vector.value[0]}/"
    #     if self.attack_complexity:
    #         ret_str += f"AC:{self.attack_complexity.value[0]}/"
    #     if self.privileges_required:
    #         ret_str += f"PR:{self.privileges_required.value[0]}/"
    #     if self.user_interaction:
    #         ret_str += f"UI:{self.user_interaction.value[0]}/"
    #     if self.scope:
    #         ret_str += f"S:{self.scope.value[0]}/"
    #     if self.confidentiality_impact:
    #         ret_str += f"C:{self.confidentiality_impact.value[0]}/"
    #     if self.integrity_impact:
    #         ret_str += f"I:{self.integrity_impact.value[0]}/"
    #     if self.availability_impact:
    #         ret_str += f"A:{self.availability_impact.value[0]}"
    #     if ret_str[-1] == '/':
    #         ret_str = ret_str[:-1]
    #     return ret_str
