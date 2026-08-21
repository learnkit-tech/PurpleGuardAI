from pathlib import Path

def analyze_dependencies(project_path):
    project_path = Path(project_path)

    dependencies = {
        "python": [],
        "node": [],
        "rust": [],
        "go": []
    }

    # Python
    req = project_path / "requirements.txt"
    if req.exists():
        for line in req.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                dependencies["python"].append(line)

    # Node.js
    package = project_path / "package.json"
    if package.exists():
        dependencies["node"].append("package.json detected")

    # Rust
    cargo = project_path / "Cargo.toml"
    if cargo.exists():
        dependencies["rust"].append("Cargo.toml detected")

    # Go
    gomod = project_path / "go.mod"
    if gomod.exists():
        dependencies["go"].append("go.mod detected")

    return dependencies
