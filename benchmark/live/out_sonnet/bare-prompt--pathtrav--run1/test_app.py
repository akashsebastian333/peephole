from app import app


def test_download():
    client = app.test_client()

    ok = client.get("/download?name=hello.txt")
    assert ok.status_code == 200

    for payload in ["../CLAUDE.md", "..%2fCLAUDE.md", "/etc/passwd"]:
        r = client.get(f"/download?name={payload}")
        assert r.status_code == 404, payload


if __name__ == "__main__":
    test_download()
    print("ok")
