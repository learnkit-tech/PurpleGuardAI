from pathlib import Path

def detect_framework(project_path):
    root = Path(project_path)

    if (root / "manage.py").exists():
        return "Django"

    if (root / "package.json").exists():
        text = (root / "package.json").read_text(errors="ignore")

        if "next" in text:
            return "Next.js"

        if "express" in text:
            return "Express"

        if "react" in text:
            return "React"

    if (root / "requirements.txt").exists():
        req = (root / "requirements.txt").read_text(errors="ignore").lower()

        if "fastapi" in req:
            return "FastAPI"

        if "flask" in req:
            return "Flask"

    return "Unknown"

