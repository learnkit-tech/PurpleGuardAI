from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CodeLocation:
    file: str
    line: int
    code: str


@dataclass
class AttackNode:
    id: str
    kind: str
    name: str
    location: Optional[CodeLocation] = None
    description: str = ""


@dataclass
class AttackPath:
    id: str
    title: str
    category: str
    severity: str
    confidence: float
    nodes: List[AttackNode] = field(default_factory=list)
    impact: str = ""
    status: str = "POTENTIAL"


@dataclass
class HackerReport:
    project: str
    files_analyzed: int = 0
    attack_surfaces: List[AttackNode] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    suspicious_code: List[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "project": self.project,
            "files_analyzed": self.files_analyzed,

            "attack_surfaces": [
                {
                    "id": node.id,
                    "kind": node.kind,
                    "name": node.name,
                    "location": (
                        {
                            "file": node.location.file,
                            "line": node.location.line,
                            "code": node.location.code,
                        }
                        if node.location else None
                    ),
                    "description": node.description,
                }
                for node in self.attack_surfaces
            ],

            "attack_paths": [
                {
                    "id": path.id,
                    "title": path.title,
                    "category": path.category,
                    "severity": path.severity,
                    "confidence": path.confidence,
                    "status": path.status,
                    "impact": path.impact,

                    "nodes": [
                        {
                            "id": node.id,
                            "kind": node.kind,
                            "name": node.name,
                            "location": (
                                {
                                    "file": node.location.file,
                                    "line": node.location.line,
                                    "code": node.location.code,
                                }
                                if node.location else None
                            ),
                            "description": node.description,
                        }
                        for node in path.nodes
                    ],
                }
                for path in self.attack_paths
            ],

            "suspicious_code": self.suspicious_code,
        }
