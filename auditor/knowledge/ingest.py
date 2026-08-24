import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ValidationError

from ..models.rule import Condition, Severity
from ..models.baseline import SecurityBaselineModel
from .repository import save_source, save_control, list_controls, approve_control, reject_control
from ..parsers.llm.client import _import_anthropic, LLMResponseError, LLMUnavailableError

class CandidateControl(BaseModel):
    control_id: str = Field(description="The compliance control identifier, e.g. CIS-IOS-1.2.2")
    framework: str = Field(description="The compliance framework name, e.g. CIS")
    framework_version: str = Field(description="The framework version, e.g. 1.0")
    title: str = Field(description="Title of the control")
    requirement: str = Field(description="Exact compliance requirement statement")
    description: str = Field(description="Detailed description")
    severity: str = Field(description="Severity: low, medium, or high")
    vendor: str = Field(description="Target vendor, e.g. Cisco")
    platform: str = Field(description="Target platform, e.g. cisco_ios")
    evidence_requirements: List[str] = Field(description="List of baseline fields used in condition, e.g. ['telnet_enabled']")
    pass_condition: Condition = Field(description="JSON condition for PASS, e.g. {'field': 'telnet_enabled', 'operator': 'is_false'}")
    remediation_summary: str = Field(description="Remediation description")
    remediation_cli: List[str] = Field(description="Vendor CLI remediation commands to fix the control")
    references: List[str] = Field(default_factory=list, description="References, URLs, section names")
    source_document: str = Field(description="Name of the source document")
    source_version: str = Field(description="Version of the source document")
    source_location: str = Field(description="Page, section or clause reference in source")

class CandidateExtraction(BaseModel):
    controls: List[CandidateControl]

def validate_candidate_control(candidate: CandidateControl) -> None:
    """Validate candidate control schema, baseline fields, condition grammar, and values."""
    # 1. Validate severity
    if candidate.severity.lower() not in ("low", "medium", "high"):
        raise ValidationError(f"Invalid severity value: {candidate.severity}")
        
    # 2. Validate evidence requirements are valid baseline fields
    known_fields = set(SecurityBaselineModel.observable_fields())
    for field in candidate.evidence_requirements:
        if field.split(".")[0] not in known_fields:
            raise ValueError(f"Field '{field}' is not a valid SecurityBaselineModel field.")
            
    # 3. Check if fields in pass_condition match evidence_requirements
    from ..models.rule import referenced_fields
    try:
        cond_fields = referenced_fields(candidate.pass_condition)
        for f in cond_fields:
            if f not in candidate.evidence_requirements:
                raise ValueError(f"Field '{f}' in pass_condition not listed in evidence_requirements.")
    except Exception as exc:
        raise ValueError(f"Condition validation failed: {exc}")

def ingest_from_json(file_path: Path) -> List[int]:
    """Ingest candidate controls from a structured JSON file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"JSON source file not found: {path}")
        
    content = path.read_text(encoding="utf-8")
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON file format: {exc}")
        
    # Standardize data structure
    candidates = []
    if isinstance(data, dict):
        if "controls" in data:
            candidates = data["controls"]
        else:
            candidates = [data]
    elif isinstance(data, list):
        candidates = data
    else:
        raise ValueError("JSON must be a control dictionary or a list of control dictionaries.")
        
    source_id = save_source(
        source_name=path.name,
        source_type="file",
        source_url_or_path=str(path.resolve()),
        source_version="1.0",
        source_date=datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).date().isoformat(),
        content_hash=content_hash,
        validation_status="APPROVED"
    )
    
    control_ids = []
    for idx, raw_control in enumerate(candidates):
        try:
            candidate = CandidateControl.model_validate(raw_control)
            validate_candidate_control(candidate)
            
            c_id = save_control(
                framework=candidate.framework,
                framework_version=candidate.framework_version,
                control_id=candidate.control_id,
                title=candidate.title,
                requirement=candidate.requirement,
                description=candidate.description,
                severity=candidate.severity,
                vendor=candidate.vendor,
                platform=candidate.platform,
                evidence_requirements=candidate.evidence_requirements,
                pass_condition=candidate.pass_condition.model_dump(),
                remediation_summary=candidate.remediation_summary,
                remediation_cli=candidate.remediation_cli,
                references=candidate.references,
                source_id=source_id,
                source_location=candidate.source_location,
                validation_status="VALIDATION_PENDING"
            )
            control_ids.append(c_id)
        except Exception as exc:
            raise ValueError(f"Control #{idx} failed validation: {exc}")
            
    return control_ids

def ingest_from_text_with_llm(file_path: Path, api_key: Optional[str] = None) -> List[int]:
    """Ingest compliance document by calling LLM to extract candidate controls."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Source document not found: {path}")
        
    text = path.read_text(encoding="utf-8")
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    
    anthropic = _import_anthropic()
    
    # Resolve API Key
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise LLMUnavailableError(
            "No Anthropic credentials found. Please set ANTHROPIC_API_KEY environment variable "
            "to extract knowledge using an LLM."
        )
        
    client = anthropic.Anthropic(api_key=key)
    
    system_prompt = (
        "You are a network security compliance expert.\n"
        "Your task is to analyze the compliance document and extract structured compliance controls.\n"
        "Each control must map to a single vendor (e.g. Cisco, Juniper, Fortinet, Arista, Sonic) "
        "and platform (e.g. cisco_ios, juniper_junos, fortinet_fortios, arista_eos, sonic).\n"
        "Define a deterministic pass_condition using valid fields of the SecurityBaselineModel.\n"
        "Fields list: " + ", ".join(SecurityBaselineModel.observable_fields()) + "\n"
        "Ensure pass_condition uses valid operators: equals, not_equals, is_true, is_false, "
        "greater_than, greater_or_equal, less_than, less_or_equal, in_set, not_in_set, subset_of, "
        "contains_any, contains_none, is_empty, is_not_empty, matches_regex."
    )
    
    print(f"Calling LLM ({client.base_url}) to extract compliance controls from document...")
    try:
        response = client.messages.parse(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4000,
            system=system_prompt,
            messages=[{"role": "user", "content": f"Extract controls from the following document:\n\n{text}"}],
            output_format=CandidateExtraction
        )
    except Exception as exc:
        raise LLMResponseError(f"LLM extraction request failed: {exc}") from exc
        
    extraction = response.parsed_output
    if not extraction or not extraction.controls:
        raise LLMResponseError("LLM returned no candidate controls.")
        
    source_id = save_source(
        source_name=path.name,
        source_type="file",
        source_url_or_path=str(path.resolve()),
        source_version="1.0",
        source_date=datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).date().isoformat(),
        content_hash=content_hash,
        validation_status="APPROVED"
    )
    
    control_ids = []
    for idx, candidate in enumerate(extraction.controls):
        try:
            validate_candidate_control(candidate)
            
            c_id = save_control(
                framework=candidate.framework,
                framework_version=candidate.framework_version,
                control_id=candidate.control_id,
                title=candidate.title,
                requirement=candidate.requirement,
                description=candidate.description,
                severity=candidate.severity,
                vendor=candidate.vendor,
                platform=candidate.platform,
                evidence_requirements=candidate.evidence_requirements,
                pass_condition=candidate.pass_condition.model_dump(),
                remediation_summary=candidate.remediation_summary,
                remediation_cli=candidate.remediation_cli,
                references=candidate.references,
                source_id=source_id,
                source_location=candidate.source_location,
                validation_status="VALIDATION_PENDING"
            )
            
            # Since this remediation was suggested by LLM, mark its provenance
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE controls SET validation_status = 'VALIDATION_PENDING' WHERE id = ?", (c_id,))
            conn.commit()
            conn.close()
            
            control_ids.append(c_id)
        except Exception as exc:
            print(f"Warning: Control #{idx} ({candidate.control_id}) failed validation and was skipped: {exc}")
            
    return control_ids
