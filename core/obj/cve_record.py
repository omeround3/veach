import json
from pyrsistent import immutable
from core.obj.node import Node
from core.analyser.enums import BaseMetricAttributes
from core.matcher.enums import CVEAttributes
from core.analyser.enums import BaseMetricAttributes
from core.utils import *


class CVERecord():
    def __init__(self, cve_raw: dict) -> None:
        """deserialization class for CVE record"""
        self._id = get_attribute(cve_raw, CVEAttributes.ID)
        self._base_metric_v2 = get_attribute(cve_raw, CVEAttributes.CVSSV2)
        self._base_metric_v3 = get_attribute(cve_raw, CVEAttributes.CVSSV3)

        self._published_date = get_attribute(
            cve_raw, CVEAttributes.PUBLISHED_DATE)

        self._lastModified_date = get_attribute(
            cve_raw, CVEAttributes.LAST_MODIFIED_DATE)

        self._nodes: list[Node] = []

        for node in get_attribute(cve_raw, CVEAttributes.NODES):
            self._nodes.append(Node(node))

    def __str__(self) -> str:
        return self._id

    def get_metrics(self, cvss: BaseMetricAttributes = BaseMetricAttributes.V3):
        if cvss == BaseMetricAttributes.V3:
            return self._base_metric_v3
        elif cvss == BaseMetricAttributes.V2:
            return self._base_metric_v2

    def __hash__(self) -> int:
        return self._id.__hash__()

    def __eq__(self, __o: object) -> bool:
        return self._id == __o._id
