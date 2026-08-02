from app import app


def test_download():
    client = app.test_client()
    assert client.get("/download?name=sample.txt").status_code == 200
    assert client.get("/download?name=../app.py").status_code in (403, 404)


if __name__ == "__main__":
    test_download()
    print("ok")
