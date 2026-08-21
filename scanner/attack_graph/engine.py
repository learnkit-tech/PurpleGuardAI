class AttackGraphEngine:
    def __init__(self):
        self.nodes = []
        self.edges = []

    def add_finding(self, finding):
        self.nodes.append(finding)

    def connect(self, source, target, reason):
        self.edges.append({
            "from": source,
            "to": target,
            "reason": reason
        })

    def build(self, findings):
        for finding in findings:
            self.add_finding(finding)

        self._analyze_relationships()

        return {
            "nodes": self.nodes,
            "edges": self.edges
        }

    def _analyze_relationships(self):
        for first in self.nodes:
            for second in self.nodes:
                if first == second:
                    continue

                if self._can_chain(first, second):
                    self.connect(
                        first,
                        second,
                        "Potential attack path"
                    )

    def _can_chain(self, first, second):
        first_type = first.get("category", "").lower()
        second_type = second.get("category", "").lower()

        if "authentication" in first_type and "database" in second_type:
            return True

        if "password" in first_type and "admin" in second_type:
            return True

        if "file upload" in first_type:
            return True

        return False
