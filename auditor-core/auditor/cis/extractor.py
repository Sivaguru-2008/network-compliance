"""
CIS Benchmark PDF extractor.

Extracts structured CIS recommendations from benchmark PDFs using pdfplumber.
All extracted data carries provenance back to the source PDF (file, hash, page).
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pdfplumber

from auditor.cis.schema import (
    AssessmentStatus,
    CISBenchmark,
    CISRecommendation,
    EvaluationType,
    Profile,
    SourceProvenance,
)

# --------------------------------------------------------------------------- #
#  Internal helpers
# --------------------------------------------------------------------------- #

_REC_ID_RE = re.compile(r"^(\d+\.\d+(?:\.\d+)*)\s+(.*)")
_ASSESS_RE = re.compile(r"\((Automated|Manual)\)")

_SECTION_HEADERS = {
    "Profile Applicability:",
    "Description:",
    "Rationale:",
    "Impact:",
    "Audit:",
    "Remediation:",
    "Default Value:",
    "References:",
    "CIS Controls:",
    "Additional Information:",
}

_SECTION_KEY_MAP = {
    "Profile Applicability:": "profile",
    "Description:": "description",
    "Rationale:": "rationale",
    "Impact:": "impact",
    "Audit:": "audit",
    "Remediation:": "remediation",
    "Default Value:": "default_value",
    "References:": "references",
    "CIS Controls:": "cis_controls",
    "Additional Information:": "additional_info",
}


@dataclass
class _RawRec:
    """Intermediate representation of a recommendation before field parsing."""

    rule_id: str
    title: str
    assessment: str
    start_page: int  # 1-indexed
    raw_lines: List[Tuple[int, str]] = field(default_factory=list)  # (page, line)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _clean(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _section_label(line: str) -> Optional[str]:
    stripped = line.strip()
    for header in _SECTION_HEADERS:
        if stripped == header or stripped.startswith(header):
            return header
    return None


# --------------------------------------------------------------------------- #
#  Top-level section mapping (recommendation ID → section name)
# --------------------------------------------------------------------------- #

_FORTIGATE_SECTIONS = {
    "1": "Network Settings",
    "2": "System Settings",
    "2.1": "General Settings",
    "2.2": "Password Policy",
    "2.3": "SNMP",
    "2.4": "Administrators and Admin Profiles",
    "2.5": "High Availability",
    "3": "Policy and Objects",
    "4": "Security Profiles",
    "4.1": "Intrusion Prevention System (IPS)",
    "4.2": "Antivirus",
    "4.3": "DNS Filter",
    "4.4": "Application Control",
    "5": "Security Fabric",
    "5.1": "Automation",
    "5.2": "Security Fabric",
    "6": "VPN",
    "6.1": "SSL VPN",
    "7": "Logs and Reports",
    "7.1": "Enable Logging",
    "7.2": "Encrypt Logs Sent to FortiAnalyzer / FortiManager",
    "7.3": "Centralized Logging and Reporting",
}


def _resolve_section(rule_id: str) -> str:
    parts = rule_id.split(".")
    for depth in range(len(parts) - 1, 0, -1):
        candidate = ".".join(parts[:depth])
        if candidate in _FORTIGATE_SECTIONS:
            return _FORTIGATE_SECTIONS[candidate]
    return ""


# --------------------------------------------------------------------------- #
#  Phase 1: Locate recommendation headers in the body pages
# --------------------------------------------------------------------------- #


def _locate_recommendations(
    pdf: pdfplumber.PDF,
    body_start: int = 16,
    body_end: int = 158,
) -> List[_RawRec]:
    """
    Scan body pages for recommendation headers.

    Handles multi-line titles where (Automated|Manual) is on the next line.
    Returns list sorted by page appearance order.
    """
    all_lines: List[Tuple[int, str]] = []
    for page_idx in range(body_start, min(body_end, len(pdf.pages))):
        text = pdf.pages[page_idx].extract_text() or ""
        for line in text.split("\n"):
            all_lines.append((page_idx + 1, line))

    recs: List[_RawRec] = []
    i = 0
    while i < len(all_lines):
        page, line = all_lines[i]
        m = _REC_ID_RE.match(line.strip())
        if m:
            rec_id = m.group(1)
            rest = m.group(2).strip()
            am = _ASSESS_RE.search(rest)
            if am:
                title = _clean(rest[: am.start()])
                recs.append(_RawRec(rec_id, title, am.group(1), page))
            elif i + 1 < len(all_lines):
                _, next_line = all_lines[i + 1]
                am2 = _ASSESS_RE.search(next_line.strip())
                if am2:
                    extra = next_line.strip()[: am2.start()].strip()
                    title = _clean(rest + " " + extra) if extra else _clean(rest)
                    recs.append(_RawRec(rec_id, title, am2.group(1), page))
                    i += 1
        i += 1

    return recs


# --------------------------------------------------------------------------- #
#  Phase 2: Extract raw text blocks for each recommendation
# --------------------------------------------------------------------------- #


def _extract_raw_blocks(
    pdf: pdfplumber.PDF,
    recs: List[_RawRec],
    body_end: int = 158,
) -> None:
    """Populate each _RawRec.raw_lines with text between its header and the next."""
    page_cache: Dict[int, List[str]] = {}

    def _get_lines(page_num: int) -> List[str]:
        if page_num not in page_cache:
            if page_num - 1 < len(pdf.pages):
                text = pdf.pages[page_num - 1].extract_text() or ""
                page_cache[page_num] = text.split("\n")
            else:
                page_cache[page_num] = []
        return page_cache[page_num]

    for idx, rec in enumerate(recs):
        end_page = recs[idx + 1].start_page if idx + 1 < len(recs) else min(body_end, len(pdf.pages))

        collecting = False
        for page_num in range(rec.start_page, end_page + 1):
            lines = _get_lines(page_num)
            for line in lines:
                stripped = line.strip()
                if not collecting:
                    if _REC_ID_RE.match(stripped):
                        m = _REC_ID_RE.match(stripped)
                        if m and m.group(1) == rec.rule_id:
                            collecting = True
                    continue

                if idx + 1 < len(recs) and page_num == recs[idx + 1].start_page:
                    m = _REC_ID_RE.match(stripped)
                    if m and m.group(1) == recs[idx + 1].rule_id:
                        return_early = True
                        break

                rec.raw_lines.append((page_num, stripped))
            else:
                continue
            break


# --------------------------------------------------------------------------- #
#  Phase 3: Parse structured fields from raw text
# --------------------------------------------------------------------------- #


def _parse_fields(rec: _RawRec) -> Dict[str, str]:
    """Split raw_lines into named sections based on CIS field headers."""
    fields: Dict[str, List[str]] = {}
    current_key: Optional[str] = None

    for _page, line in rec.raw_lines:
        label = _section_label(line)
        if label:
            current_key = _SECTION_KEY_MAP[label]
            remainder = line.strip()[len(label) :].strip()
            fields.setdefault(current_key, [])
            if remainder:
                fields[current_key].append(remainder)
        elif current_key:
            fields.setdefault(current_key, []).append(line)

    return {k: _clean("\n".join(v)) for k, v in fields.items()}


def _parse_profiles(profile_text: str) -> List[Profile]:
    profiles = []
    if "Level 1" in profile_text:
        profiles.append(Profile.LEVEL_1)
    if "Level 2" in profile_text:
        profiles.append(Profile.LEVEL_2)
    return profiles or [Profile.LEVEL_1]


def _parse_references(ref_text: str) -> List[str]:
    urls = re.findall(r"https?://\S+", ref_text)
    return urls


# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #


def extract_fortigate(
    pdf_path: str | Path,
    *,
    body_start_page: int = 16,
    body_end_page: int = 158,
) -> CISBenchmark:
    """
    Extract all CIS recommendations from the FortiGate 7.0.x benchmark PDF.

    Args:
        pdf_path: Path to CIS_Fortigate_7.0.x_Benchmark_v1.4.0.pdf
        body_start_page: 0-indexed page where recommendation bodies begin (default 16)
        body_end_page: 0-indexed page where recommendation bodies end (default 158)

    Returns:
        CISBenchmark with all recommendations and provenance.
    """
    pdf_path = Path(pdf_path)
    source_hash = _sha256(pdf_path)
    warnings: List[str] = []

    with pdfplumber.open(pdf_path) as pdf:
        total_pages = len(pdf.pages)

        # Phase 1: locate headers
        recs = _locate_recommendations(pdf, body_start_page, body_end_page)
        if not recs:
            raise ValueError(f"No CIS recommendations found in {pdf_path.name}")

        # Phase 2: extract raw blocks
        _extract_raw_blocks(pdf, recs, body_end_page)

        # Phase 3: parse fields into structured recommendations
        recommendations: List[CISRecommendation] = []
        for rec in recs:
            fields = _parse_fields(rec)

            if not fields:
                warnings.append(f"{rec.rule_id}: no structured fields extracted (page {rec.start_page})")
                continue

            profiles = _parse_profiles(fields.get("profile", ""))
            references = _parse_references(fields.get("references", ""))

            provenance = SourceProvenance(
                file=pdf_path.name,
                hash=source_hash,
                page=rec.start_page,
                benchmark_id="CIS_Fortigate_7.0.x",
                benchmark_version="1.4.0",
            )

            cis_rec = CISRecommendation(
                benchmark_id="CIS_Fortigate_7.0.x",
                vendor="Fortinet",
                product="FortiGate",
                benchmark_version="1.4.0",
                rule_id=rec.rule_id,
                title=rec.title,
                assessment_status=AssessmentStatus(rec.assessment),
                profile=profiles,
                description=fields.get("description", ""),
                rationale=fields.get("rationale", ""),
                impact=fields.get("impact", ""),
                audit=fields.get("audit", ""),
                remediation=fields.get("remediation", ""),
                default_value=fields.get("default_value", ""),
                references=references,
                cis_controls=fields.get("cis_controls", ""),
                additional_info=fields.get("additional_info", ""),
                section=_resolve_section(rec.rule_id),
                source=provenance,
            )
            recommendations.append(cis_rec)

        if len(recommendations) < 50:
            warnings.append(
                f"Only {len(recommendations)} recommendations extracted; expected ~56. "
                "Some may have been missed due to formatting."
            )

    return CISBenchmark(
        benchmark_id="CIS_Fortigate_7.0.x",
        vendor="Fortinet",
        product="FortiGate",
        product_version="7.0.x",
        benchmark_version="1.4.0",
        publication_date="2025-12-17",
        source_file=pdf_path.name,
        source_hash=source_hash,
        pages=total_pages,
        profiles=["Level 1", "Level 2"],
        sections=[
            "1 Network Settings",
            "2 System Settings",
            "3 Policy and Objects",
            "4 Security Profiles",
            "5 Security Fabric",
            "6 VPN",
            "7 Logs and Reports",
        ],
        recommendations=recommendations,
        extraction_warnings=warnings,
    )


def save_benchmark(benchmark: CISBenchmark, output_path: str | Path) -> Path:
    """Serialize a CISBenchmark to JSON with full provenance."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = benchmark.model_dump(mode="json")
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return output_path
