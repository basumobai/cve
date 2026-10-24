"""Bounded, non-following website discovery for common control-panel layouts.

Never reads the contents of site files: only directory names and manifest existence.
A website does not need a package manager to be included in the site inventory.
"""
from pathlib import Path

IGNORE_DIRS = frozenset({
    ".git", ".svn", ".hg", ".next", ".nuxt", ".output", ".cache",
    "node_modules", "vendor", "venv", ".venv", "__pycache__",
    "logs", "log", "cache", "tmp", "temp", "backup", "backups",
    "uploads", "upload", "storage", "dist", "build", "coverage",
})
PHP_MARKERS = ("composer.lock", "composer.json", "artisan", "wp-config.php")
NODE_MARKERS = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
                "yarn.lock", "bun.lock", "bun.lockb", "package.json")
PROJECT_MARKERS = PHP_MARKERS + NODE_MARKERS


def classify_project(path):
    """Identify basic tech via filenames without opening secrets or source code."""
    markers = [name for name in PROJECT_MARKERS if (path / name).is_file()]
    technologies = []
    if any(name in markers for name in PHP_MARKERS):
        technologies.append("PHP")
    if any(name in markers for name in NODE_MARKERS):
        technologies.append("Node.js")
    if "artisan" in markers:
        technologies.append("Laravel")
    if "wp-config.php" in markers:
        technologies.append("WordPress")
    return technologies, markers


def _children(path):
    """Read only direct children; do not follow directory symlinks."""
    return sorted(path.iterdir(), key=lambda child: child.name)


def discover_projects(site_path, max_depth=3, max_dirs=3000):
    """Find manifests at site root or bounded nested subdirectories."""
    projects = []
    warnings = []
    stack = [(site_path, 0)]
    visited = 0
    while stack:
        path, depth = stack.pop()
        if path.is_symlink():
            warnings.append(f"symlink skipped: {path}")
            continue
        visited += 1
        if visited > max_dirs:
            warnings.append(f"directory walk limit ({max_dirs}) hit: {site_path}")
            break
        tech, markers = classify_project(path)
        if markers:
            projects.append({"path": str(path), "technologies": tech,
                             "markers": markers})
        if depth >= max_depth:
            continue
        try:
            children = _children(path)
        except OSError as exc:
            warnings.append(f"cannot list {path}: {type(exc).__name__}")
            continue
        for child in reversed(children):
            if child.is_symlink():
                # Do not traverse release symlinks or anything outside the document root.
                if child.name not in IGNORE_DIRS and not child.name.startswith("."):
                    warnings.append(f"symlink skipped: {child}")
                continue
            if child.name in IGNORE_DIRS or child.name.startswith("."):
                continue
            if child.is_dir():
                stack.append((child, depth + 1))
    return projects, warnings


def discover_websites(roots, max_sites=100, max_depth=3, max_projects=250):
    """Discover immediate site directories and nested projects.

    Return: (sites, warnings). Missing roots are explicit warnings. Do not assume
    such paths are secure or silently report an empty scan as safe.
    """
    sites = []
    warnings = []
    seen = set()
    project_count = 0
    for name in roots:
        root = Path(name).expanduser()
        if not root.is_absolute():
            warnings.append(f"not an absolute website root: {name}")
            continue
        if not root.is_dir():
            warnings.append(f"website root missing/unreadable: {root}")
            continue
        if root.is_symlink():
            warnings.append(f"website root is a symlink, skipped: {root}")
            continue
        try:
            children = _children(root)
        except OSError as exc:
            warnings.append(f"cannot list website root {root}: {type(exc).__name__}")
            continue
        # Detect a single site deployed directly at the root too.
        if classify_project(root)[1] or (root / "index.php").is_file() or (root / "index.html").is_file():
            children = [root] + children
        for child in children:
            if len(sites) >= max_sites:
                warnings.append(f"website limit ({max_sites}) reached; remaining sites not scanned")
                return sites, warnings
            if child.is_symlink():
                if not child.name.startswith("."):
                    warnings.append(f"site symlink skipped: {child}")
                continue
            if not child.is_dir() or child.name.startswith(".") or child.name in IGNORE_DIRS:
                continue
            canonical = str(child.resolve())
            if canonical in seen:
                continue
            seen.add(canonical)
            projects, detail = discover_projects(child, max_depth=max_depth)
            warnings.extend(detail)
            remaining = max(0, max_projects - project_count)
            if len(projects) > remaining:
                warnings.append(f"project limit ({max_projects}) reached; some projects not audited under {child}")
                projects = projects[:remaining]
            project_count += len(projects)
            sites.append({"name": child.name, "path": str(child),
                          "projects": projects, "technologies": sorted({
                              tech for project in projects for tech in project["technologies"]
                          })})
    return sites, warnings
