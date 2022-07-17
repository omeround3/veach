from core.obj.cpe_record import CPERecord


class Node:
    def __init__(self, node: dict) -> None:
        """deserialization class for Node record"""
        self.operator = None
        self.cpe_match: list[CPERecord] = []

        if 'operator' in node:
            self.operator = node['operator']
        if 'cpe_match' in node:
            cpe_matches = node['cpe_match']
            for cpe_match in cpe_matches:
                self.cpe_match.append(CPERecord(cpe_match))
