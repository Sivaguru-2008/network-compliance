"""HTTP routes for the dashboard. Orchestration only -- no auditing happens here.

Every endpoint below does the same three things: validate what the client sent,
call the core, and serialize what came back.  The two calls that matter are
:func:`auditor.ingest.ingest_paths` -- byte for byte the function the CLI's
``--bulk`` path calls -- and :func:`auditor.report.pdf.write_device_pdf`, which
is the Step 9 renderer.  Neither is wrapped, adjusted or second-guessed, and
there is no code path here that can produce a finding, a count or a verdict that
the CLI would not produce from the same files.

Both are reached through their defining module rather than through a
``from ... import`` binding captured at import time. That is not stylistic: it
keeps the seam visible, so a test can replace either one and prove that the
endpoints really do delegate rather than quietly reimplement.

What the client is told is the published contract and nothing invented beside
it.  ``/api/inventory/{job_id}`` returns the Step 8 ``DeviceInventory`` verbatim
-- same keys, same counts, same device order the CLI writes with
``--inventory``.  Where a job id has to travel with it, it rides in an envelope
*around* the contract rather than as a field inserted into it.
"""

from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from .. import __version__
from .. import ingest as ingest_module
from ..models.inventory import DeviceStatus
from ..report import pdf as pdf_module
from ..rules import available_frameworks
from .jobs import JobStore
from .uploads import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_REQUEST_BYTES,
    UploadRejected,
    save_upload,
)

#: Evaluated when the client selects nothing, matching the CLI's own default so
#: the two frontends cannot disagree about what "no framework given" means.
DEFAULT_FRAMEWORK = ingest_module.pipeline.DEFAULT_FRAMEWORK

STATIC_DIR = Path(__file__).parent / "static"


def _normalize_frameworks(raw: List[str]) -> List[str]:
    """Accept ``cis``, ``CIS``, or ``cis,stig`` and return canonical names.

    Case and comma-splitting are handled because a checkbox form, a curl command
    and a hand-written fetch all spell a list differently, and none of those is
    the user making a mistake.
    """
    names: List[str] = []
    for value in raw:
        for part in str(value).split(","):
            part = part.strip()
            if part and part.upper() not in {n.upper() for n in names}:
                names.append(part)
    return names


def _validate_frameworks(names: List[str]) -> List[str]:
    """Resolve requested names against the installed packs, or fail once.

    A misspelled framework is one mistake, not one per device -- the same
    reasoning, and the same behaviour, as the CLI's bulk path.
    """
    if not names:
        return [DEFAULT_FRAMEWORK]

    known = {name.upper(): name for name in available_frameworks()}
    unknown = [name for name in names if name.upper() not in known]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown framework(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(known.values()))}."
            ),
        )
    return [known[name.upper()] for name in names]


def create_app(store_root: Optional[Path] = None) -> FastAPI:
    """Build the application. ``store_root`` lets a test own its job directory."""
    app = FastAPI(
        title="netaudit dashboard",
        version=__version__,
        description=(
            "Upload network configurations, get a device inventory and per-device "
            "compliance findings. A presentation layer over the same audit core the "
            "netaudit CLI runs -- two frontends, one engine."
        ),
    )
    store = JobStore(store_root)
    app.state.store = store

    # -- views --------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> HTMLResponse:
        return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))

    @app.get("/api/frameworks")
    async def frameworks() -> JSONResponse:
        """What the checkboxes offer: discovered from the rule packs, not hardcoded."""
        return JSONResponse(
            {"frameworks": available_frameworks(), "default": DEFAULT_FRAMEWORK}
        )

    # -- upload -------------------------------------------------------------

    @app.post("/api/upload")
    async def upload(
        files: List[UploadFile] = File(...),
        frameworks: List[str] = Form(default=[]),
    ) -> JSONResponse:
        """Ingest one or many configurations and return the resulting inventory.

        The response is an envelope, because the caller needs both the job id and
        the inventory and only one of them belongs inside the Step 8 contract.
        ``inventory`` is that contract, verbatim.
        """
        if not files:
            raise HTTPException(status_code=400, detail="No files were uploaded.")
        if len(files) > MAX_FILES:
            raise HTTPException(
                status_code=413,
                detail=f"Too many files: {len(files)}. The limit is {MAX_FILES} per upload.",
            )

        selected = _validate_frameworks(_normalize_frameworks(frameworks))

        job_id, root = store.new_job_dir()
        config_dir = root / "configs"

        # Uploads are streamed straight into the job directory under names this
        # server generated. Nothing is written anywhere else, at any point.
        saved: List[Path] = []
        budget = MAX_REQUEST_BYTES
        try:
            for index, item in enumerate(files):
                path = await save_upload(item, config_dir, index, budget_remaining=budget)
                budget -= path.stat().st_size
                saved.append(path)
        except UploadRejected as exc:
            store.discard(job_id)
            raise HTTPException(status_code=413, detail=exc.detail) from exc

        # The core call. Explicit paths, exactly as `netaudit --bulk a.conf b.conf`
        # passes them, so every uploaded file yields a record whatever its
        # extension -- and so a malformed one yields a parse_error row instead of
        # taking the batch down with it.
        inventory = await run_in_threadpool(
            ingest_module.ingest_paths,
            [str(path) for path in saved],
            selected,
        )

        job = store.record(job_id, root, inventory)
        return JSONResponse(
            {
                "job_id": job.job_id,
                "frameworks": selected,
                "inventory": inventory.to_dict(),
            }
        )

    # -- retrieval ----------------------------------------------------------

    def _require_job(job_id: str):
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"No such job: {job_id}")
        return job

    @app.get("/api/inventory/{job_id}")
    async def inventory(job_id: str) -> JSONResponse:
        """The Step 8 DeviceInventory for one upload, unchanged.

        Identical to what ``netaudit --bulk --inventory out.json`` writes for the
        same files: same device list, same counts, same duplicate groups.
        """
        return JSONResponse(_require_job(job_id).inventory.to_dict())

    @app.get("/api/device/{job_id}/{device_id}")
    async def device(job_id: str, device_id: int) -> JSONResponse:
        """One DeviceRecord: identity, findings with their evidence origin, summaries.

        The record is the Step 8 model serialized as-is. Provenance is not a field
        this layer adds -- it is already on every piece of evidence, put there by
        the parser that made the observation.
        """
        job = _require_job(job_id)
        record = job.device_at(device_id)
        if record is None:
            raise HTTPException(
                status_code=404, detail=f"No device {device_id} in job {job_id}."
            )
        return JSONResponse(
            {
                "job_id": job.job_id,
                "device_id": device_id,
                "pdf_url": f"/api/device/{job.job_id}/{device_id}/pdf",
                "device": record.model_dump(mode="json"),
            }
        )

    @app.get("/api/device/{job_id}/{device_id}/pdf")
    async def device_pdf(job_id: str, device_id: int) -> FileResponse:
        """The Step 9 per-device PDF, rendered by the core and served as a download.

        Written into, and served from, this job's own directory, addressed by an
        integer index. There is no code path from a client string to a filesystem
        path, so there is nothing here for a crafted request to point at.
        """
        job = _require_job(job_id)
        record = job.device_at(device_id)
        if record is None:
            raise HTTPException(
                status_code=404, detail=f"No device {device_id} in job {job_id}."
            )

        destination = job.pdf_dir / f"{device_id}.pdf"
        if not destination.is_file():
            job.pdf_dir.mkdir(parents=True, exist_ok=True)
            try:
                await run_in_threadpool(
                    pdf_module.write_device_pdf, record, destination, version=__version__
                )
            except pdf_module.PdfUnavailableError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc

        # The download name is the core's own scheme, so a file saved from the
        # dashboard and one written by `netaudit --pdf-dir` are named alike.
        names = pdf_module.pdf_filenames(job.inventory.devices)
        return FileResponse(
            destination,
            media_type="application/pdf",
            filename=names[device_id],
        )

    return app


app = create_app()


__all__ = ["app", "create_app"]
