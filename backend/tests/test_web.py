import pytest

from siem import create_app
from siem.config import Config
from siem.web import CONTENT_SECURITY_POLICY


@pytest.fixture
def dist(tmp_path):
    folder = tmp_path / "dist"
    (folder / "assets").mkdir(parents=True)
    (folder / "index.html").write_text("<!doctype html><title>Security Dashboard</title>")
    (folder / "assets" / "index-abc123.js").write_text("console.log('app')")
    (folder / "theme.js").write_text("// theme")
    (tmp_path / "secret.txt").write_text("outside the build")
    return folder


def make_client(tmp_path, dist_dir):
    config = Config(
        DB_PATH=str(tmp_path / "w.db"),
        START_BACKGROUND_JOBS=False,
        SECRET_KEY="test-secret",
        ADMIN_PASSWORD="correct-horse-battery",
        FRONTEND_DIST=str(dist_dir),
    )
    return create_app(config).test_client()


def test_serves_dashboard_and_assets(tmp_path, dist):
    client = make_client(tmp_path, dist)

    page = client.get("/")
    assert page.status_code == 200
    assert b"Security Dashboard" in page.data
    assert page.headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY
    assert "no-cache" in page.headers["Cache-Control"]

    asset = client.get("/assets/index-abc123.js")
    assert asset.status_code == 200
    assert "immutable" in asset.headers["Cache-Control"]
    assert client.get("/theme.js").status_code == 200


def test_dashboard_routes_fall_back_to_the_app(tmp_path, dist):
    client = make_client(tmp_path, dist)
    for path in ("/alerts/12", "/events?ip=203.0.113.9", "/rules"):
        res = client.get(path, headers={"Accept": "text/html"})
        assert res.status_code == 200, path
        assert b"Security Dashboard" in res.data


def test_api_and_missing_files_are_not_the_app(tmp_path, dist):
    client = make_client(tmp_path, dist)
    res = client.get("/api/nope")
    assert res.status_code == 404
    assert res.is_json
    assert client.get("/missing.png", headers={"Accept": "image/png"}).status_code == 404
    for path in ("/../secret.txt", "/assets/../../secret.txt", "/%2e%2e/secret.txt"):
        assert b"outside the build" not in client.get(path).data, path
    assert client.get("/api/health").get_json() == {"status": "ok"}


def test_security_headers_on_api_responses(tmp_path, dist):
    res = make_client(tmp_path, dist).get("/api/health")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" not in res.headers


def test_explains_missing_build(tmp_path):
    res = make_client(tmp_path, tmp_path / "no-dist").get("/")
    assert res.status_code == 404
    assert "npm run build" in res.get_json()["message"]
