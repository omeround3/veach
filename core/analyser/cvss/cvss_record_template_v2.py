from enum import Enum
from cvss_record_template import RecordTemplate


class Version(Enum):
    V2_0 = '2.0'


class AccessVector(Enum):
    ADJACENT_NETWORK = 'ADJACENT_NETWORK'
    NETWORK = 'NETWORK'
    LOCAL = 'LOCAL'


class AccessComplexity(Enum):
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'


class Authentication(Enum):
    MULTIPLE = 'MULTIPLE'
    NONE = 'NONE'
    SINGLE = 'SINGLE'


class ConfidentialityImpact(Enum):
    COMPLETE = 'COMPLETE'
    PARTIAL = 'PARTIAL'
    NONE = 'NONE'


class IntegrityImpact(Enum):
    COMPLETE = 'COMPLETE'
    PARTIAL = 'PARTIAL'
    NONE = 'NONE'


class AvailabilityImpact(Enum):
    COMPLETE = 'COMPLETE'
    PARTIAL = 'PARTIAL'
    NONE = 'NONE'


class RecordTemplateV2(RecordTemplate):
    def __init__(self,
                 version: Version = None,
                 access_vector: AccessVector = None,
                 access_complexity: AccessComplexity = None,
                 authentication: Authentication = None,
                 confidentiality_impact: ConfidentialityImpact = None,
                 integrity_impact: IntegrityImpact = None,
                 availability_impact: AvailabilityImpact = None,
                 # base_score: float = None,
                 ):
        self.version = version
        self.access_vector = access_vector
        self.access_complexity = access_complexity
        self.authentication = authentication
        self.confidentiality_impact = confidentiality_impact
        self.integrity_impact = integrity_impact
        self.availability_impact = availability_impact
        # self.base_score = base_score
