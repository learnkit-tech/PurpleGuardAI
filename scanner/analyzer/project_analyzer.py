from pathlib import Path
from .language_detector import detect_languages
from .framework_detector import detect_framework
from .dependency_analyzer import analyze_dependencies
from .attack_surface import discover_attack_surface


class ProjectAnalyzer:
    def __init__(self, project_path):
        self.project_path = Path(project_path)

    def analyze(self):
        return {
            "languages": detect_languages(self.project_path),
            "framework": detect_framework(self.project_path),
            "dependencies": analyze_dependencies(self.project_path),
            "attack_surface": discover_attack_surface(self.project_path)
        }
