import os

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "__pycache__", "dist", "build",
            "target", ".next", ".nuxt", ".gradle", ".idea", ".vs", "bower_components", "coverage"}
TEXT_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".php", ".rb", ".java", ".kt", ".go", ".rs", ".c", ".h",
    ".cpp", ".hpp", ".cs", ".swift", ".m", ".scala", ".sh", ".bash", ".yml", ".yaml", ".json", ".toml",
    ".ini", ".cfg", ".env", ".txt", ".md", ".html", ".sql", ".tf", ".dockerfile", "",
}
MANIFESTS = {
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "requirements.txt": "PyPI", "pipfile.lock": "PyPI", "poetry.lock": "PyPI",
    "go.mod": "Go", "go.sum": "Go", "composer.json": "Packagist", "composer.lock": "Packagist",
    "gemfile.lock": "RubyGems", "pom.xml": "Maven", "build.gradle": "Maven", "cargo.lock": "crates.io",
}


def walk_files(root, max_files, max_kb):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if count >= max_files:
                return
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > max_kb * 1024 or size == 0:
                continue
            if ext not in TEXT_EXT and name.lower() not in MANIFESTS:
                continue
            count += 1
            yield path, name.lower()


def read_text(path, limit_kb):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit_kb * 1024)
    except OSError:
        return ""
