SAMPLE = [
    {
        "ts": "2026-10-19T10:00:00Z", "source": "sshd", "host": "web-01",
        "category": "authentication", "action": "login", "outcome": "failure",
        "severity": "low", "user": "root", "src_ip": "203.0.113.7", "dst_port": 22,
        "message": "Failed password for root from 203.0.113.7 port 51234 ssh2",
    },
    {
        "ts": "2026-10-19T10:05:00Z", "source": "sshd", "host": "web-01",
        "category": "authentication", "action": "login", "outcome": "success",
        "severity": "info", "user": "alice", "src_ip": "198.51.100.20",
        "message": "Accepted publickey for alice from 198.51.100.20",
    },
    {
        "ts": "2026-10-19T11:00:00Z", "source": "nginx", "host": "web-01",
        "category": "web", "action": "http_request", "severity": "high",
        "src_ip": "203.0.113.7", "dst_ip": "10.0.0.5", "dst_port": 443,
        "message": "GET /../../etc/passwd 400",
    },
]


def test_health(client):
    assert client.get("/api/health").get_json() == {"status": "ok"}


def test_ingest_requires_api_key(ingest):
    assert ingest({"message": "x"}, key="wrong").status_code == 401


def test_ingest_rejects_non_json(client):
    res = client.post("/api/ingest", data="nope", headers={"X-API-Key": "test-key"})
    assert res.status_code == 400


def test_ingest_single_and_batch(ingest, client):
    before = client.get("/api/events").get_json()["total"]  # includes the test client's own sign-in event
    res = ingest({"message": "single"})
    assert res.status_code == 202
    assert res.get_json()["accepted"] == 1

    res = ingest(SAMPLE)
    assert res.get_json()["accepted"] == 3
    assert client.get("/api/events").get_json()["total"] == before + 4


def test_ingest_partial_batch_reports_rejections(ingest):
    res = ingest([{"message": "ok"}, {"message": "bad", "src_ip": "nope"}])
    body = res.get_json()
    assert res.status_code == 202
    assert body["accepted"] == 1
    assert body["rejected"] == [{"index": 1, "error": "src_ip: not a valid IP address"}]


def test_ingest_all_invalid_is_400(ingest):
    assert ingest([{"severity": "bad"}]).status_code == 400


def test_ingest_batch_limit(ingest):
    assert ingest([{"message": str(i)} for i in range(11)]).status_code == 413


def test_events_sorted_newest_first(ingest, client):
    ingest(SAMPLE)
    events = client.get("/api/events").get_json()["events"]
    assert [e["ts"] for e in events] == sorted((e["ts"] for e in events), reverse=True)


def test_search_filters(ingest, client):
    ingest(SAMPLE)

    def total(query):
        res = client.get(f"/api/events?{query}")
        assert res.status_code == 200, res.get_json()
        return res.get_json()["total"]

    assert total("q=passwd") == 1
    assert total("q=pass") == 2            # prefix match: "password" and "passwd"
    assert total("q=etc passwd") == 1      # all words must match
    assert total("src_ip=203.0.113.7") == 2
    assert total("ip=10.0.0.5") == 1
    assert total("user=alice") == 1
    assert total("severity=high,low") == 2
    assert total("category=authentication&outcome=failure") == 1
    assert total("from=2026-10-19T10:01:00Z&to=2026-10-19T10:59:00Z") == 1


def test_search_handles_fts_syntax_safely(ingest, client):
    ingest(SAMPLE)
    res = client.get('/api/events?q=" OR ( NEAR')
    assert res.status_code == 200


def test_search_validation_errors(client):
    assert client.get("/api/events?severity=urgent").status_code == 400
    assert client.get("/api/events?from=yesterday").status_code == 400
    assert client.get("/api/events?limit=abc").status_code == 400


def test_pagination(ingest, client):
    ingest(SAMPLE)
    body = client.get("/api/events?host=web-01&limit=2&page=2").get_json()
    assert body["total"] == 3
    assert len(body["events"]) == 1
    assert body["page"] == 2


def test_event_detail(ingest, client):
    event_id = ingest(SAMPLE).get_json()["ids"][0]
    assert client.get(f"/api/events/{event_id}").get_json()["user"] == "root"
    assert client.get("/api/events/9999").status_code == 404


def test_unknown_route_returns_json(client):
    res = client.get("/api/nope")
    assert res.status_code == 404
    assert "error" in res.get_json()


def test_ingest_raw_lines(client):
    body = (
        "<38>Oct 19 10:15:02 web-01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n"
        "\n"
        "something unparsed\n"
    )
    res = client.post("/api/ingest/raw?host=edge-1", data=body, headers={"X-API-Key": "test-key"})
    assert res.status_code == 202
    assert res.get_json()["accepted"] == 2
    events = client.get("/api/events?host=edge-1").get_json()["events"]
    assert [e["category"] for e in events] == ["unknown"]


def test_ingest_raw_forced_format_rejects_mismatch(client):
    res = client.post("/api/ingest/raw?format=sshd", data="not ssh", headers={"X-API-Key": "test-key"})
    assert res.status_code == 400
    assert res.get_json()["rejected"][0]["line"] == 1


def test_ingest_raw_requires_key_and_known_format(client):
    assert client.post("/api/ingest/raw", data="x").status_code == 401
    res = client.post("/api/ingest/raw?format=xml", data="x", headers={"X-API-Key": "test-key"})
    assert res.status_code == 400


def test_ingest_json_with_format_and_windows(ingest, client):
    res = ingest([
        {"format": "web", "raw": '1.2.3.4 - - [19/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 10', "host": "web-02"},
        {"EventID": 4625, "Computer": "dc-01", "TargetUserName": "alice", "IpAddress": "10.0.0.8"},
        {"format": "web", "raw": 42},
    ])
    body = res.get_json()
    assert body["accepted"] == 2
    assert body["rejected"][0]["index"] == 2
    assert client.get("/api/events?source=windows&user=alice").get_json()["total"] == 1


def test_simulator_api(client):
    scenarios = client.get("/api/simulate").get_json()["scenarios"]
    assert {s["id"] for s in scenarios} >= {"brute_force", "port_scan"}
    res = client.post("/api/simulate/port_scan")
    assert res.status_code == 201
    assert res.get_json()["events"] == 60
    assert client.get("/api/events?source=firewall&limit=1").get_json()["total"] == 60
    assert client.post("/api/simulate/nope").status_code == 404


def test_demo_login_records_event(client, anon):
    assert anon.post("/api/demo/login", json={"user": "zed"}).status_code == 401
    client.post("/api/demo/login", json={"user": "zed"})
    client.post("/api/demo/login", json=["not", "an", "object"])
    assert client.get("/api/events?source=demo-api").get_json()["total"] == 2
    assert client.get("/api/events?source=demo-api&user=zed").get_json()["total"] == 1


def test_legacy_endpoints_are_gone(anon):
    assert anon.post("/api/login").status_code in (404, 405)
    assert anon.get("/api/monitor-stats").status_code == 404
