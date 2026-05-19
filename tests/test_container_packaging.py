from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


def test_dockerfile_packages_prebuilt_frontend_dist():
    dockerfile = (ROOT_DIR / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM node:" not in dockerfile
    assert "AS frontend-builder" not in dockerfile
    assert "npm ci" not in dockerfile
    assert "npm run build" not in dockerfile
    assert "COPY --chown=postara:postara frontend/dist ./frontend/dist" in dockerfile
    assert "COPY --chown=postara:postara frontend/dist-site ./frontend/dist-site" in dockerfile
    assert "frontend/dist" in dockerfile
    assert "frontend/dist-site" in dockerfile
    assert 'PYTHONPATH="/app/src"' in dockerfile
    assert "favicon.svg icon-app.svg" in dockerfile


def test_compose_image_can_be_overridden_for_pulled_package():
    compose = (ROOT_DIR / "docker-compose.yml").read_text(encoding="utf-8")

    assert 'image: "${POSTARA_IMAGE:-ghcr.io/jmluang/postara:latest}"' in compose
    assert "build:" not in compose


def test_github_actions_publish_container_package_to_ghcr():
    workflow = (ROOT_DIR / ".github" / "workflows" / "docker.yml").read_text(encoding="utf-8")

    assert "ghcr.io" in workflow
    assert "packages: write" in workflow
    assert "docker/build-push-action" in workflow
    assert "github.repository" in workflow
    assert "type=raw,value=latest" in workflow
