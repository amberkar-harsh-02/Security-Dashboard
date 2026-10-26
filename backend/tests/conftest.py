import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from siem import create_app  # noqa: E402
from siem.config import Config  # noqa: E402

API_KEY = "test-key"
ADMIN_PASSWORD = "correct-horse-battery"


@pytest.fixture
def app(tmp_path):
    config = Config(
        DB_PATH=str(tmp_path / "test.db"),
        INGEST_API_KEY=API_KEY,
        START_BACKGROUND_JOBS=False,
        MAX_BATCH_SIZE=10,
        SECRET_KEY="test-secret",
        ADMIN_USER="admin",
        ADMIN_PASSWORD=ADMIN_PASSWORD,
        STREAM_POLL_SECONDS=0.05,
        STREAM_MAX_SECONDS=0.5,
    )
    return create_app(config)


@pytest.fixture
def anon(app):
    """A client that has not signed in."""
    return app.test_client()


@pytest.fixture
def client(app):
    """A signed-in analyst. Sends the CSRF token on every request."""
    test_client = app.test_client()
    res = test_client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert res.status_code == 200, res.get_json()
    test_client.environ_base["HTTP_X_CSRF_TOKEN"] = res.get_json()["csrf_token"]
    return test_client


@pytest.fixture
def ingest(anon):
    def send(payload, key=API_KEY):
        return anon.post("/api/ingest", json=payload, headers={"X-API-Key": key})

    return send
