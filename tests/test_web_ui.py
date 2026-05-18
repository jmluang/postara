from pathlib import Path

from fastapi.testclient import TestClient

from postara.accounts import AccountService
from postara.api import create_app


def test_frontend_routes_serve_landing_and_workspace(tmp_path: Path):
    app_dist = tmp_path / "app-dist"
    site_dist = tmp_path / "site-dist"
    (app_dist / "assets").mkdir(parents=True)
    (site_dist / "assets").mkdir(parents=True)
    (app_dist / "assets" / "app.js").write_text("console.log('postara app')", encoding="utf-8")
    (site_dist / "assets" / "site.js").write_text("console.log('postara site')", encoding="utf-8")
    (app_dist / "index.html").write_text(
        """<!doctype html>
<html lang="en">
<body data-postara-app="react-workspace">
  <div id="root"></div>
  <script type="module" src="/assets/app.js"></script>
</body>
</html>
""",
        encoding="utf-8",
    )
    (site_dist / "index.html").write_text(
        """<!doctype html>
<html lang="en">
<body data-postara-site="landing">
  <div id="root"></div>
  <script type="module" src="/assets/site.js"></script>
</body>
</html>
""",
        encoding="utf-8",
    )

    client = TestClient(create_app(accounts=AccountService(), frontend_dist=app_dist, frontend_site_dist=site_dist))

    root_response = client.get("/")
    privacy_response = client.get("/privacy")
    app_response = client.get("/app")

    assert root_response.status_code == 200
    assert root_response.headers["content-type"].startswith("text/html")
    assert 'data-postara-site="landing"' in root_response.text
    assert "/assets/site.js" in root_response.text
    assert privacy_response.status_code == 200
    assert 'data-postara-site="landing"' in privacy_response.text
    assert app_response.status_code == 200
    assert 'data-postara-app="react-workspace"' in app_response.text
    assert "/assets/app.js" in app_response.text
    assert "/admin/accounts" not in app_response.text
    assert "Admin Token" not in app_response.text

    app_asset_response = client.get("/assets/app.js")
    site_asset_response = client.get("/assets/site.js")

    assert app_asset_response.status_code == 200
    assert "postara app" in app_asset_response.text
    assert site_asset_response.status_code == 200
    assert "postara site" in site_asset_response.text


def test_workspace_serves_brand_icons():
    client = TestClient(create_app(accounts=AccountService()))

    favicon = client.get("/favicon.svg")
    app_icon = client.get("/icon-app.svg")

    assert favicon.status_code == 200
    assert favicon.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in favicon.text
    assert app_icon.status_code == 200
    assert app_icon.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in app_icon.text


def test_frontend_does_not_persist_raw_api_keys():
    bundled_sources = "\n".join(path.read_text(encoding="utf-8") for path in Path("frontend/dist/assets").glob("*.js"))

    assert "localStorage.setItem(localApiKeyId" not in bundled_sources
    assert "localStorage.getItem(localApiKeyId" not in bundled_sources
