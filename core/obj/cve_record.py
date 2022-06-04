from pyrsistent import immutable
from core.obj.node import Node
from core.analyser.enums import BaseMetricAttributes
from core.matcher.enums import CVEAttributes
from core.analyser.enums import BaseMetricAttributes


class CVERecord():
    def __init__(self, cve_raw: dict) -> None:
        """deserialization class for CVE record"""
        # no need to keep this much info, will be trimmed later
        self._id = None
        self._cve = None
        self._configurations = None
        self._impact = None
        self._published_date = None
        self._lastModified_date = None

        self._base_metric_v2 = None
        self._base_metric_v3 = None

        self._nodes: list[Node] = []

        if CVEAttributes.CVE in cve_raw:
            self._cve = cve_raw[CVEAttributes.CVE]
            if 'CVE_data_meta' in self._cve:
                meta_data = self._cve['CVE_data_meta']
                if 'ID' in meta_data:
                    self._id = meta_data['ID']

        if CVEAttributes.CONFIGURATION in cve_raw:
            self._configurations = cve_raw[CVEAttributes.CONFIGURATION]
            if 'nodes' in self._configurations:
                nodes = self._configurations['nodes']
                for node in nodes:
                    self._nodes.append(Node(node))

        if CVEAttributes.IMPACT in cve_raw:
            self._impact = cve_raw[CVEAttributes.IMPACT]
            if BaseMetricAttributes.V2 in self._impact:
                self._base_metric_v2 = self._impact[BaseMetricAttributes.V2]
            if BaseMetricAttributes.V3 in self._impact:
                self._base_metric_v3 = self._impact[BaseMetricAttributes.V3]

        if CVEAttributes.PUBLISHED_DATE in cve_raw:
            self._published_date = cve_raw[CVEAttributes.PUBLISHED_DATE]

        if CVEAttributes.LAST_MODIFIED_DATE in cve_raw:
            self._lastModified_date = cve_raw[CVEAttributes.LAST_MODIFIED_DATE]

    def __str__(self) -> str:
        return self._id

    def get_metrics(self, cvss: BaseMetricAttributes):
        if cvss == BaseMetricAttributes.V3 and self._base_metric_v3:
            return self._base_metric_v3
        elif cvss == BaseMetricAttributes.V2 and self._base_metric_v2:
            return self._base_metric_v2
        else:
            return None

    def __hash__(self) -> int:
        return self._id.__hash__()

    def __eq__(self, __o: object) -> bool:
        return self._id == __o._id
