from __future__ import annotations

from pathlib import Path


def default_frontend_dist() -> Path:
    return Path(__file__).resolve().parents[2] / "frontend" / "dist"


def default_frontend_site_dist() -> Path:
    backend_site_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist-site"
    if backend_site_dist.exists():
        return backend_site_dist
    return Path(__file__).resolve().parents[3] / "frontend" / "dist-site"


def brand_icon_path(filename: str) -> Path:
    if filename not in {"favicon.svg", "icon-app.svg"}:
        raise ValueError("unsupported brand icon")
    return Path(__file__).resolve().parents[2] / filename


def index_html(frontend_dist: Path) -> str:
    index_path = frontend_dist / "index.html"
    if not index_path.exists():
        return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Postara</title>
</head>
<body data-postara-app="missing-build">
  <main>
    <h1>Postara frontend build is missing.</h1>
    <p>Copy the prebuilt app-only frontend bundle into frontend/dist, then restart Postara.</p>
  </main>
</body>
</html>
"""
    return index_path.read_text(encoding="utf-8")


def frontend_asset_path(asset_path: str, *asset_roots: Path) -> Path | None:
    for root in asset_roots:
        if not root.exists():
            continue
        candidate = (root / asset_path).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    return None
