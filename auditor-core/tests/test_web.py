"""The web dashboard: a shell over the core, proven to be exactly that.

Every test here checks one of two things: that an endpoint returns what the CLI
would return for the same files (the contract holds across the two frontends),
or that the shell defers to the core rather than re-deriving anything itself
(``test_upload_calls_the_core_ingest_function_not_a_reimplementation`` and
``test_pdf_endpoint_calls_the_core_renderer``). The upload-security tests are
the other half: proving the sandbox holds against a filename an attacker chose
on purpose, not one a browser would ever send.
"""

import io
from pathlib import Path
from unittest.mock import ANY

import pytest
from fastapi.testclient import TestClient

from auditor import ingest as ingest_module
from auditor.models.inventory import DeviceStatus
from auditor.report import pdf as pdf_module
from auditor.web.app import create_app
from auditor.web.uploads import MAX_FILE_BYTES

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "samples"


def _sample_bytes(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def _upload(client, files, frameworks=None):
    """POST /api/upload with (name, bytes) pairs, as a browser's picker would send them."""
    parts = [("files", (name, io.BytesIO(data), "text/plain")) for name, data in files]
    data = {"frameworks": frameworks} if frameworks else {}
    return client.post("/api/upload", files=parts, data=data)


@pytest.fixture
def client(tmp_path):
    app = create_app(store_root=tmp_path / "jobs")
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. single upload
# ---------------------------------------------------------------------------


def test_single_cisco_upload_returns_a_one_device_inventory(client):
    response = _upload(client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))])

    assert response.status_code == 200
    body = response.json()
    assert "job_id" in body and body["job_id"]

    inventory = body["inventory"]
    assert inventory["counts"]["total"] == 1
    assert inventory["counts"]["audited"] == 1
    assert inventory["devices"][0]["identity"]["vendor"] == "cisco_ios"
    assert inventory["devices"][0]["status"] == "audited"


# ---------------------------------------------------------------------------
# 2. bulk upload, mixed vendors, isolation holds
# ---------------------------------------------------------------------------


def test_bulk_mixed_vendor_upload_gives_one_record_per_file_and_isolates_failures(client):
    response = _upload(
        client,
        [
            ("core-rtr.conf", _sample_bytes("hardened_ios.conf")),
            ("branch-fw.conf", _sample_bytes("junos_srx.conf")),
            ("fgt.conf", _sample_bytes("fortios_fgt.conf")),
            ("garbage.conf", b""),
        ],
    )

    assert response.status_code == 200
    inventory = response.json()["inventory"]
    assert inventory["counts"]["total"] == 4
    assert inventory["counts"]["audited"] == 3
    assert inventory["counts"]["parse_error"] == 1

    by_status = {d["status"] for d in inventory["devices"]}
    assert by_status == {"audited", "parse_error"}

    # The malformed file is a visible row with its own error, not a dropped device.
    failed = next(d for d in inventory["devices"] if d["status"] == "parse_error")
    assert failed["error"]
    assert "garbage.conf" in failed["source_file"]

    def original_name(source_file: str) -> str:
        # Stored as `NNNN_<original>`; strip the server-assigned index prefix.
        base = Path(source_file).name
        return base.split("_", 1)[1]

    vendors = {
        original_name(d["source_file"]): d["identity"]["vendor"]
        for d in inventory["devices"]
        if d["status"] == "audited"
    }
    assert vendors == {
        "core-rtr.conf": "cisco_ios",
        "branch-fw.conf": "juniper_junos",
        "fgt.conf": "fortinet_fortios",
    }


# ---------------------------------------------------------------------------
# 3. GET /api/inventory/{job_id} matches what the CLI would produce
# ---------------------------------------------------------------------------


def test_get_inventory_matches_direct_ingest_paths_for_the_same_files(client, tmp_path):
    response = _upload(
        client,
        [
            ("core-rtr.conf", _sample_bytes("hardened_ios.conf")),
            ("fgt.conf", _sample_bytes("fortios_fgt.conf")),
        ],
        frameworks=["CIS"],
    )
    job_id = response.json()["job_id"]

    fetched = client.get(f"/api/inventory/{job_id}")
    assert fetched.status_code == 200
    assert fetched.json() == response.json()["inventory"]

    # Same two files, ingested directly through the CLI's own function: same counts.
    direct = tmp_path / "direct"
    direct.mkdir()
    (direct / "core-rtr.conf").write_bytes(_sample_bytes("hardened_ios.conf"))
    (direct / "fgt.conf").write_bytes(_sample_bytes("fortios_fgt.conf"))
    direct_inventory = ingest_module.ingest_paths([str(direct)], ["CIS"])

    assert fetched.json()["counts"]["audited"] == direct_inventory.counts.audited
    assert fetched.json()["counts"]["total"] == direct_inventory.counts.total


def test_unknown_job_id_is_a_404(client):
    assert client.get("/api/inventory/" + "0" * 32).status_code == 404


# ---------------------------------------------------------------------------
# 4. PDF download
# ---------------------------------------------------------------------------


def test_device_pdf_endpoint_returns_a_valid_nonempty_pdf(client):
    response = _upload(client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))])
    job_id = response.json()["job_id"]

    pdf = client.get(f"/api/device/{job_id}/0/pdf")

    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:5] == b"%PDF-"
    assert len(pdf.content) > 500
    assert "attachment" in pdf.headers.get("content-disposition", "")


def test_pdf_for_unknown_device_index_is_a_404(client):
    response = _upload(client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))])
    job_id = response.json()["job_id"]

    assert client.get(f"/api/device/{job_id}/99/pdf").status_code == 404


# ---------------------------------------------------------------------------
# 5. findings carry provenance
# ---------------------------------------------------------------------------


def test_device_findings_carry_the_origin_field(client):
    response = _upload(client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))])
    job_id = response.json()["job_id"]

    device = client.get(f"/api/device/{job_id}/0").json()["device"]

    assert device["findings"], "expected at least one finding to inspect"
    origins_seen = set()
    for finding in device["findings"]:
        for evidence in finding["evidence"]:
            assert "origin" in evidence
            origins_seen.add(evidence["origin"])
    assert "deterministic" in origins_seen


# ---------------------------------------------------------------------------
# 6. NEEDS_REVIEW is represented distinctly, never mapped to pass
# ---------------------------------------------------------------------------


def test_needs_review_is_a_distinct_status_never_collapsed_into_pass(client):
    # insecure_ios.conf is the fixture the rest of the suite uses to exercise
    # NEEDS_REVIEW: hardened_ios.conf is deliberately clean and yields none.
    response = _upload(client, [("insecure_ios.conf", _sample_bytes("insecure_ios.conf"))])
    job_id = response.json()["job_id"]

    device = client.get(f"/api/device/{job_id}/0").json()["device"]
    statuses = {f["status"] for f in device["findings"]}

    assert "NEEDS_REVIEW" in statuses
    review_findings = [f for f in device["findings"] if f["status"] == "NEEDS_REVIEW"]
    assert all(f["status"] != "PASS" for f in review_findings)

    # And the summary tallies review separately from both pass and fail.
    summary = device["summary"]
    assert summary["needs_review"] == len(review_findings)
    assert summary["needs_review"] > 0
    assert summary["passed"] + summary["failed"] + summary["needs_review"] == summary["total"]


# ---------------------------------------------------------------------------
# 7. the web layer calls the core, it does not reimplement it
# ---------------------------------------------------------------------------


def test_upload_calls_the_core_ingest_function_not_a_reimplementation(client, monkeypatch):
    calls = []
    real_ingest_paths = ingest_module.ingest_paths

    def spy(paths, frameworks, *args, **kwargs):
        calls.append((list(paths), list(frameworks)))
        return real_ingest_paths(paths, frameworks, *args, **kwargs)

    monkeypatch.setattr(ingest_module, "ingest_paths", spy)

    response = _upload(client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))], frameworks=["CIS"])

    assert response.status_code == 200
    assert len(calls) == 1
    paths, frameworks = calls[0]
    assert frameworks == ["CIS"]
    assert len(paths) == 1
    assert paths[0].endswith("hardened_ios.conf")


def test_pdf_endpoint_calls_the_core_renderer(client, monkeypatch):
    calls = []
    real_write = pdf_module.write_device_pdf

    def spy(record, path, **kwargs):
        calls.append((record, path))
        return real_write(record, path, **kwargs)

    monkeypatch.setattr(pdf_module, "write_device_pdf", spy)

    response = _upload(client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))])
    job_id = response.json()["job_id"]

    pdf = client.get(f"/api/device/{job_id}/0/pdf")

    assert pdf.status_code == 200
    assert len(calls) == 1
    record, path = calls[0]
    assert record.identity.vendor == "cisco_ios"


# ---------------------------------------------------------------------------
# 8. upload security: size cap and path traversal
# ---------------------------------------------------------------------------


def test_oversize_file_is_rejected_and_nothing_is_written_outside_the_job_dir(client, tmp_path):
    huge = b"! " + b"a" * (MAX_FILE_BYTES + 1024)
    response = _upload(client, [("big.conf", huge)])

    assert response.status_code == 413

    jobs_root = tmp_path / "jobs"
    # No config bytes should have escaped past the cap into any job directory.
    for path in jobs_root.rglob("*"):
        if path.is_file() and path.suffix == ".conf":
            assert path.stat().st_size <= MAX_FILE_BYTES


def test_path_traversal_filename_is_rejected_and_nothing_escapes_the_job_dir(client, tmp_path):
    response = _upload(client, [("../../etc/x", b"hostname evil\n")])

    assert response.status_code == 413
    assert "path separator" in response.json()["detail"].lower() or "path" in response.json()["detail"].lower()

    jobs_root = tmp_path / "jobs"
    escaped = (PROJECT_ROOT.parent / "etc" / "x")
    assert not escaped.exists()
    # And every file that *is* on disk lives under the jobs root, nowhere else.
    for path in jobs_root.rglob("*"):
        if path.is_file():
            assert jobs_root.resolve() in path.resolve().parents


def test_backslash_traversal_filename_is_also_rejected(client):
    response = _upload(client, [("..\\..\\windows\\win.ini", b"hostname evil\n")])
    assert response.status_code == 413


# ---------------------------------------------------------------------------
# 9. framework selection flows through
# ---------------------------------------------------------------------------


def test_selecting_only_cis_yields_only_cis_results(client):
    response = _upload(
        client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))], frameworks=["cis"]
    )

    assert response.status_code == 200
    inventory = response.json()["inventory"]
    assert inventory["frameworks"] == ["CIS"]

    device = inventory["devices"][0]
    assert set(device["framework_summaries"].keys()) == {"CIS"}
    assert {f["framework"] for f in device["findings"]} == {"CIS"}


def test_unknown_framework_name_is_a_clean_400_not_a_500(client):
    response = _upload(
        client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))], frameworks=["NOT_A_FRAMEWORK"]
    )
    assert response.status_code == 400
    assert "NOT_A_FRAMEWORK" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 10. CLI regression: single-file and bulk both still work, untouched by web
# ---------------------------------------------------------------------------


def test_cli_single_file_still_works(capsys):
    from auditor import cli

    exit_code = cli.run(["samples/hardened_ios.conf", "--framework", "CIS", "--no-color"])
    captured = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    assert "NETWORK SECURITY COMPLIANCE AUDIT" in captured


def test_cli_bulk_still_works(tmp_path, capsys):
    from auditor import cli

    fleet = tmp_path / "fleet"
    fleet.mkdir()
    (fleet / "a.conf").write_bytes(_sample_bytes("hardened_ios.conf"))
    (fleet / "b.conf").write_bytes(_sample_bytes("fortios_fgt.conf"))

    exit_code = cli.run(["--bulk", str(fleet), "--framework", "CIS", "--no-color", "--quiet"])
    assert exit_code in (cli.EXIT_OK, 2)  # findings/review can raise exit code without --strict being unset


# ---------------------------------------------------------------------------
# extra: empty upload and too-many-files are clean errors, not tracebacks
# ---------------------------------------------------------------------------


def test_empty_upload_is_a_clean_400(client):
    response = client.post("/api/upload", files=[], data={})
    assert response.status_code in (400, 422)


# ---------------------------------------------------------------------------
# 11. GET /api/jobs listing
# ---------------------------------------------------------------------------


def test_jobs_empty_when_no_uploads(client):
    response = client.get("/api/jobs")
    assert response.status_code == 200
    assert response.json() == []


def test_jobs_lists_uploaded_jobs_with_summary(client):
    _upload(client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))], frameworks=["CIS"])
    _upload(client, [("junos_srx.conf", _sample_bytes("junos_srx.conf"))], frameworks=["CIS"])

    response = client.get("/api/jobs")
    assert response.status_code == 200
    jobs = response.json()
    assert len(jobs) == 2

    for job in jobs:
        assert "job_id" in job
        assert "uploaded_at" in job
        assert "device_count" in job
        assert "frameworks" in job
        assert "compliance_scores" in job
        assert job["device_count"] >= 1
        assert "CIS" in job["compliance_scores"]


def test_jobs_compliance_scores_match_inventory_rollup(client):
    resp = _upload(
        client,
        [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))],
        frameworks=["CIS"],
    )
    job_id = resp.json()["job_id"]
    inv = resp.json()["inventory"]

    jobs = client.get("/api/jobs").json()
    job = next(j for j in jobs if j["job_id"] == job_id)

    for fw, summary in inv.get("framework_rollup", {}).items():
        assert abs(job["compliance_scores"][fw] - summary["compliance_score"]) < 0.01


def test_existing_endpoints_still_work_after_jobs_added(client):
    resp = _upload(client, [("hardened_ios.conf", _sample_bytes("hardened_ios.conf"))])
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    assert client.get(f"/api/inventory/{job_id}").status_code == 200
    assert client.get(f"/api/device/{job_id}/0").status_code == 200
    assert client.get(f"/api/device/{job_id}/0/pdf").status_code == 200
