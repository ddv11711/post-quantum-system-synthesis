"""Regression checks for the separate PDF library on the Normative Base screen."""
import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from core import views
    originals = tmp_path / "normative"
    originals.mkdir()
    (originals / "base.pdf").write_bytes(b"%PDF-1.4\nexisting\n%%EOF")
    imported = tmp_path / "imported"
    monkeypatch.setattr(views, "DOCUMENTS_DIR", originals)
    monkeypatch.setattr(views, "IMPORTED_DOCUMENTS_DIR", imported)
    with override_settings(ALLOWED_HOSTS=["testserver"]):
        client = Client(enforce_csrf_checks=True)
        landing = client.get("/")
        assert landing.status_code == 200
        yield client, originals, imported


def post_pdf(client, name="Новый документ.pdf", body=b"%PDF-1.7\nhello\n%%EOF"):
    return client.post(
        "/documents/import/",
        {"files": [SimpleUploadedFile(name, body, content_type="application/pdf")]},
        HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        HTTP_ACCEPT="application/json",
    )


def test_separate_form_and_empty_imported_list(environment):
    client, original, imported = environment
    html = client.get("/").content.decode()
    assert 'id="normative-import-form"' in html
    assert 'name="files"' in html
    assert 'enctype="multipart/form-data"' in html
    assert "csrfmiddlewaretoken" in html
    assert "Импортированные документы" in html
    assert "base.pdf" in html
    assert not imported.exists()  # Initial GET never creates the upload directory.


def test_upload_stays_separate_and_can_be_downloaded(environment):
    client, originals, imported = environment
    response = post_pdf(client)
    assert response.status_code == 200, response.content
    entry = response.json()["saved"][0]
    assert entry["filename"].endswith(".pdf")
    assert (imported / entry["filename"]).exists()
    assert sorted(file.name for file in originals.iterdir()) == ["base.pdf"]
    html = client.get("/").content.decode()
    assert "Новый_документ" in html or "Новый документ" in html
    assert "Импортированные документы" in html
    download = client.get(entry["url"])
    assert download.status_code == 200
    assert download["Content-Type"] == "application/pdf"
    assert b"".join(download.streaming_content) == b"%PDF-1.7\nhello\n%%EOF"
    download.close()
    assert client.get("/documents/base.pdf/").status_code == 200
    assert client.get("/documents/imported/base.pdf/").status_code == 404


def test_duplicate_uploads_get_distinct_names(environment):
    client, _originals, imported = environment
    one = post_pdf(client).json()["saved"][0]["filename"]
    two = post_pdf(client).json()["saved"][0]["filename"]
    assert one != two
    assert (imported / one).exists() and (imported / two).exists()


def test_invalid_and_oversized_uploads_are_rejected(environment, monkeypatch):
    client, _originals, imported = environment
    assert post_pdf(client, "hack.txt").status_code == 400
    assert post_pdf(client, "fake.pdf", b"NOT A PDF").status_code == 400
    from core import views
    monkeypatch.setattr(views, "MAX_NORMATIVE_PDF_BYTES", 6)
    assert post_pdf(client).status_code == 413
    assert not imported.exists() or not list(imported.iterdir())


def test_one_invalid_file_rejects_entire_batch(environment):
    client, _originals, imported = environment
    response = client.post(
        "/documents/import/",
        {"files": [
            SimpleUploadedFile("good.pdf", b"%PDF-1.4\ncorrect"),
            SimpleUploadedFile("bad.pdf", b"not a pdf"),
        ]},
        HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        HTTP_ACCEPT="application/json",
    )
    assert response.status_code == 400
    assert not imported.exists() or not list(imported.iterdir())


def test_upload_requires_csrf_and_get_is_disallowed(environment):
    client, _originals, _imported = environment
    response = client.post("/documents/import/", {"files": [SimpleUploadedFile("new.pdf", b"%PDF-1.4")]} , HTTP_ACCEPT="application/json")
    assert response.status_code == 403
    assert client.get("/documents/import/").status_code == 405
    assert client.get("/documents/imported/../base.pdf/").status_code == 404
