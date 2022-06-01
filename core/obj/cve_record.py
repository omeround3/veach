from core.obj.node import Node


class CVERecord:
    def __init__(self, cve_raw: dict) -> None:
        # no need to keep this much info, will be trimmed later
        self._id = None
        self._cve = None
        self._configurations = None
        self._impact = None
        self._published_date = None
        self._lastModified_date = None

        self._base_metric_v2 = None
        self._base_metric_v3 = None

        self.nodes = list()

        if 'cve' in cve_raw:
            self._cve = cve_raw['cve']
            if 'CVE_data_meta' in self._cve:
                meta_data = self._cve['CVE_data_meta']
                if 'ID' in meta_data:
                    self._id = meta_data['ID']

        if 'configurations' in cve_raw:
            self._configurations = cve_raw['configurations']
            if 'nodes' in self._configurations:
                nodes = self._configurations['nodes']
                for node in nodes:
                    self.nodes.append(Node(node))

        if 'impact' in cve_raw:
            self._impact = cve_raw['impact']
            if 'baseMetricV2' in self._impact:
                self._base_metric_v2 = self._impact['baseMetricV2']
            if 'baseMetricV3' in self._impact:
                self._base_metric_v3 = self._impact['baseMetricV3']

        if 'publishedDate' in cve_raw:
            self._published_date = cve_raw['publishedDate']

        if 'publishedDate' in cve_raw:
            self._lastModified_date = cve_raw['publishedDate']

    def __str__(self) -> str:
        return self._id

    def get_nodes(self):
        return self.nodes
