from pathlib import Path

EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#",
    ".php": "PHP"
}

def detect_languages(project_path):
    found = set()

    for file in Path(project_path).rglob("*"):
        if file.suffix in EXTENSIONS:
            found.add(EXTENSIONS[file.suffix])

    return sorted(found)
