from app import app


def test_download():
    client = app.test_client()

    ok = client.get("/download?name=sample.txt")
    assert ok.status_code == 200
    assert ok.data.strip() == b"hello"

    for payload in ("../secret.txt", "..%2fsecret.txt", "/etc/passwd"):
        resp = client.get(f"/download?name={payload}")
        assert resp.status_code in (400, 404), payload


if __name__ == "__main__":
    test_download()
    print("ok")
