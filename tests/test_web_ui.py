from pathlib import Path

from fastapi.testclient import TestClient

from postara.accounts import AccountService
from postara.api import create_app


def test_app_route_serves_built_react_workspace(tmp_path: Path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log('postara')", encoding="utf-8")
    (tmp_path / "index.html").write_text(
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

    client = TestClient(create_app(accounts=AccountService(), frontend_dist=tmp_path))

    response = client.get("/app")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert 'data-postara-app="react-workspace"' in response.text
    assert '<div id="root"></div>' in response.text
    assert 'type="module"' in response.text
    assert "/assets/app.js" in response.text
    assert "/admin/accounts" not in response.text
    assert "Admin Token" not in response.text

    root_response = client.get("/", follow_redirects=False)
    assert root_response.status_code in {307, 308}
    assert root_response.headers["location"] == "/app"

    asset_response = client.get("/assets/app.js")

    assert asset_response.status_code == 200
    assert "postara" in asset_response.text


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
