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

    from ..training.mappings import LearnedMappingStore
    training_dir = Path("training")
    if store_root:
        training_dir = store_root / "training"
    store_path = training_dir / "learned_mappings.jsonl"
    app.state.mapping_store = LearnedMappingStore(store_path)

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

        # The core call. Explicit paths, using the hybrid parser and dynamically
        # resolved learned mappings from the store.
        from ..parsers import HybridParser
        def custom_parser_factory(parser_cls):
            if issubclass(parser_cls, HybridParser):
                return parser_cls(
                    training_dir=store_path.parent,
                    mapping_store=app.state.mapping_store
                )
            return parser_cls()

        inventory = await run_in_threadpool(
            ingest_module.ingest_paths,
            [str(path) for path in saved],
            selected,
            vendor="hybrid",
            parser_factory=custom_parser_factory,
        )

        job = store.record(job_id, root, inventory)
        return JSONResponse(
            {
                "job_id": job.job_id,
                "frameworks": selected,
                "inventory": inventory.to_dict(),
            }
        )

    # -- jobs listing -------------------------------------------------------

    @app.get("/api/jobs")
    async def jobs_list() -> JSONResponse:
        """Every stored job with its summary metrics, for the history panel."""
        result = []
        for jid in store.job_ids():
            job = store.get(jid)
            if job is None:
                continue
            inv = job.inventory
            scores = {
                fw: round(s.compliance_score, 2)
                for fw, s in inv.framework_rollup.items()
            }
            result.append({
                "job_id": jid,
                "uploaded_at": inv.generated_at.isoformat() if inv.generated_at else None,
                "device_count": inv.counts.total,
                "frameworks": list(inv.frameworks),
                "compliance_scores": scores,
            })
        return JSONResponse(result)

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

    # -- training endpoints --------------------------------------------------

    from pydantic import BaseModel
    from ..models.inventory import DeviceStatus
    from ..models.observation import Observation
    from ..parsers import registry
    from ..training.mappings import LearnedMapping

    class PreviewRequest(BaseModel):
        vendor: str
        pattern: str
        field: str
        extraction_strategy: str
        regex_pattern: Optional[str] = None
        original_line: str

    def get_device_config_text(job, device_id: int) -> str:
        config_dir = job.config_dir
        matching_files = list(config_dir.glob(f"{device_id:04d}_*"))
        if not matching_files:
            raise FileNotFoundError(f"Config file for device {device_id} not found in job {job.job_id}")
        return matching_files[0].read_text(encoding="utf-8", errors="replace")

    @app.get("/training", response_class=HTMLResponse, include_in_schema=False)
    async def training_view() -> HTMLResponse:
        return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))

    @app.get("/training/queue")
    async def training_queue() -> JSONResponse:
        queue = []
        for job_id in store.job_ids():
            job = store.get(job_id)
            if not job or not job.inventory:
                continue
            for idx, device in enumerate(job.inventory.devices):
                if device.status != DeviceStatus.AUDITED:
                    continue
                try:
                    config_text = get_device_config_text(job, idx)
                except Exception:
                    continue

                if not device.target or not device.target.parser:
                    continue
                try:
                    parser_cls = registry.get(device.target.parser)
                    parser = parser_cls()
                    baseline = parser.parse(config_text)
                except Exception:
                    continue

                from ..training.mappings import get_unrecognized_lines
                unrecognized = get_unrecognized_lines(config_text, baseline)

                for item in unrecognized:
                    line_num = item["line_number"]
                    line_text = item["text"]
                    # Context: 5 lines before and after
                    lines = config_text.splitlines()
                    start = max(0, line_num - 6)
                    end = min(len(lines), line_num + 5)
                    context_lines = []
                    for i in range(start, end):
                        context_lines.append(f"Line {i+1}: {lines[i]}")
                    context = "\n".join(context_lines)

                    queue.append({
                        "id": f"{job_id}_{idx}_{line_num}",
                        "job_id": job_id,
                        "device_id": idx,
                        "line_number": line_num,
                        "vendor": device.identity.vendor or device.target.vendor,
                        "device_identity": device.display_name,
                        "field": "Unknown",
                        "status": "NEEDS_REVIEW",
                        "source_line": line_text,
                        "excerpt": line_text,
                        "context": context,
                        "reason": "Pattern unrecognized by deterministic parser.",
                    })
        return JSONResponse(queue)



    @app.post("/training/preview")
    async def training_preview(req: PreviewRequest) -> JSONResponse:
        from ..models.baseline import SecurityBaselineModel, ParserProvenance
        from ..training.mappings import resolve_learned_mappings
        import re

        if req.field not in SecurityBaselineModel.observable_fields():
            raise HTTPException(status_code=400, detail=f"Unknown baseline field: {req.field}")

        if req.extraction_strategy == "regex":
            if not req.regex_pattern:
                raise HTTPException(status_code=400, detail="Regex pattern is required for regex extraction strategy.")
            try:
                re.compile(req.regex_pattern)
            except re.error as e:
                raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")

        dummy_provenance = ParserProvenance(
            parser_name="preview",
            parser_version="1.0.0",
            vendor=req.vendor,
            os_family="unknown"
        )
        dummy_baseline = SecurityBaselineModel(provenance=dummy_provenance)

        mapping = LearnedMapping(
            mapping_id="preview-temp",
            vendor=req.vendor,
            pattern=req.pattern,
            field=req.field,
            extraction_strategy=req.extraction_strategy,
            regex_pattern=req.regex_pattern,
            approval_state="approved",
            status="approved"
        )

        class TempMappingStore:
            def get_active_approved_mappings(self):
                return [mapping]

        resolved_baseline = resolve_learned_mappings(
            config_text=req.original_line,
            baseline=dummy_baseline,
            store=TempMappingStore()
        )

        obs = getattr(resolved_baseline, req.field)
        if obs.detected:
            return JSONResponse({
                "result": "FOUND",
                "extracted_value": obs.value,
                "evidence": "line 1"
            })
        else:
            return JSONResponse({
                "result": "NOT_FOUND",
                "extracted_value": None,
                "evidence": "Pattern did not match the original configuration line."
            })

    @app.post("/training")
    async def create_mapping_endpoint(mapping: LearnedMapping) -> JSONResponse:
        try:
            saved = app.state.mapping_store.create_mapping(mapping)
            return JSONResponse(saved.model_dump(mode="json"))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/training/{id}/approve")
    async def training_approve(id: str) -> JSONResponse:
        mapping = app.state.mapping_store.approve_mapping(id)
        if not mapping:
            raise HTTPException(status_code=404, detail="Mapping not found")
        return JSONResponse(mapping.model_dump(mode="json"))

    @app.post("/training/{id}/reject")
    async def training_reject(id: str) -> JSONResponse:
        latest = app.state.mapping_store.retrieve_mapping(id)
        if not latest:
            raise HTTPException(status_code=404, detail="Mapping not found")
        rejected = latest.model_copy(update={
            "status": "rejected",
            "approval_state": "rejected",
            "version": latest.version + 1
        })
        app.state.mapping_store._records.append(rejected)
        app.state.mapping_store._resolve_conflicts()
        app.state.mapping_store.save()
        return JSONResponse(rejected.model_dump(mode="json"))

    @app.post("/training/{id}/disable")
    async def training_disable(id: str) -> JSONResponse:
        mapping = app.state.mapping_store.disable_mapping(id)
        if not mapping:
            raise HTTPException(status_code=404, detail="Mapping not found")
        return JSONResponse(mapping.model_dump(mode="json"))

    @app.post("/training/{id}/delete")
    async def training_delete(id: str) -> JSONResponse:
        deleted = app.state.mapping_store.delete_mapping(id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Mapping not found")
        return JSONResponse({"status": "deleted"})

    @app.get("/training/history")
    async def training_history() -> JSONResponse:
        mappings = app.state.mapping_store.list_mappings()
        return JSONResponse([m.model_dump(mode="json") for m in mappings])

    @app.get("/training/{id}")
    async def training_item(id: str) -> JSONResponse:
        parts = id.split("_")
        if len(parts) < 3:
            raise HTTPException(status_code=400, detail="Invalid queue item ID format")
        job_id = parts[0]
        try:
            device_idx = int(parts[1])
            line_num = int(parts[2])
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid queue item ID format")

        job = store.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        device = job.device_at(device_idx)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        try:
            config_text = get_device_config_text(job, device_idx)
        except Exception:
            raise HTTPException(status_code=404, detail="Config file not found")

        lines = config_text.splitlines()
        if line_num < 1 or line_num > len(lines):
            raise HTTPException(status_code=404, detail="Line number out of range")

        line_text = lines[line_num - 1].strip()

        start = max(0, line_num - 6)
        end = min(len(lines), line_num + 5)
        context_lines = []
        for i in range(start, end):
            context_lines.append(f"Line {i+1}: {lines[i]}")
        context = "\n".join(context_lines)

        return JSONResponse({
            "id": id,
            "job_id": job_id,
            "device_id": device_idx,
            "line_number": line_num,
            "vendor": device.identity.vendor or (device.target.vendor if device.target else "unknown"),
            "device_identity": device.display_name,
            "field": "Unknown",
            "status": "NEEDS_REVIEW",
            "source_line": line_text,
            "excerpt": line_text,
            "context": context,
            "reason": "Pattern unrecognized by deterministic parser.",
        })

    return app


app = create_app()


__all__ = ["app", "create_app"]
