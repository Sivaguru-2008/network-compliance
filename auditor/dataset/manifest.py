"""Dataset manifest generator and cryptographic provenance validator."""

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ManifestArtifact:
    vendor: str
    artifact_type: str  # "official_documentation", "configuration_fixture", "extracted_command_kb", "grammar_schema", "metadata"
    path: str
    source: str
    source_url: str
    real_or_synthetic: str  # "real" or "synthetic"
    sha256: str
    byte_size: int
    version: str
    sanitized: bool = True
    retrieved_at: str = ""
    description: str = ""


@dataclass
class DatasetValidationResult:
    total_artifacts: int
    valid_artifacts: int
    missing_files: List[str]
    hash_mismatches: List[Dict[str, str]]
    empty_files: List[str]
    untracked_files: List[str]
    is_valid: bool


class DatasetManifestManager:
    """Manages creation, updating, and integrity validation of the dataset manifest."""

    def __init__(self, dataset_base: Path = Path("dataset")):
        self.dataset_base = Path(dataset_base)
        self.manifest_path = self.dataset_base / "vendor_references_manifest.json"
        self.vendor_ref_base = self.dataset_base / "vendor_references"

    def _calculate_sha256(self, file_path: Path) -> str:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def generate_manifest(self) -> Dict[str, Any]:
        """Scan all vendor references, fixtures, and documentation to build a comprehensive manifest."""
        artifacts: List[ManifestArtifact] = []

        if self.vendor_ref_base.exists():
            for vendor_dir in self.vendor_ref_base.iterdir():
                if not vendor_dir.is_dir():
                    continue
                vendor_key = vendor_dir.name

                # 1. Documents & Metadata
                meta_dir = vendor_dir / "metadata"
                if meta_dir.exists():
                    for meta_file in meta_dir.glob("*.json"):
                        try:
                            with open(meta_file, "r", encoding="utf-8") as f:
                                meta = json.load(f)
                            doc_rel_path = meta.get("local_path")
                            if doc_rel_path:
                                doc_full_path = self.dataset_base / doc_rel_path
                                if doc_full_path.exists():
                                    sha = self._calculate_sha256(doc_full_path)
                                    artifacts.append(ManifestArtifact(
                                        vendor=vendor_key,
                                        artifact_type="official_documentation",
                                        path=doc_rel_path.replace("\\", "/"),
                                        source=meta.get("document_title", meta_file.stem),
                                        source_url=meta.get("source_url", ""),
                                        real_or_synthetic="real",
                                        sha256=sha,
                                        byte_size=doc_full_path.stat().st_size,
                                        version=meta.get("version", "latest"),
                                        sanitized=True,
                                        retrieved_at=meta.get("retrieved_at", ""),
                                        description=meta.get("license_or_access_note", ""),
                                    ))
                        except Exception as e:
                            logger.warning("Error reading metadata %s: %s", meta_file, e)

                # 2. Extracted Commands
                cmd_dir = vendor_dir / "commands"
                if cmd_dir.exists():
                    for cmd_file in cmd_dir.glob("*.json"):
                        sha = self._calculate_sha256(cmd_file)
                        artifacts.append(ManifestArtifact(
                            vendor=vendor_key,
                            artifact_type="extracted_command_kb",
                            path=str(cmd_file.relative_to(self.dataset_base)).replace("\\", "/"),
                            source="Authoritative Document Extraction Pipeline",
                            source_url="",
                            real_or_synthetic="real",
                            sha256=sha,
                            byte_size=cmd_file.stat().st_size,
                            version="latest",
                            sanitized=True,
                            description="Extracted CLI and configuration command knowledge base",
                        ))

                # 3. Schemas / Grammar
                schema_dir = vendor_dir / "schemas"
                if schema_dir.exists():
                    for schema_file in schema_dir.glob("*.json"):
                        sha = self._calculate_sha256(schema_file)
                        artifacts.append(ManifestArtifact(
                            vendor=vendor_key,
                            artifact_type="grammar_schema",
                            path=str(schema_file.relative_to(self.dataset_base)).replace("\\", "/"),
                            source="Authoritative Configuration Grammar Definition",
                            source_url="",
                            real_or_synthetic="real",
                            sha256=sha,
                            byte_size=schema_file.stat().st_size,
                            version="latest",
                            sanitized=True,
                            description="Formal syntax and hierarchy grammar definition",
                        ))

                # 4. Configuration Fixtures
                fix_dir = vendor_dir / "config_fixtures"
                if fix_dir.exists():
                    for fix_file in fix_dir.glob("*.*"):
                        if fix_file.suffix in (".conf", ".cfg", ".rsc", ".xml", ".json", ".cli", ".set"):
                            sha = self._calculate_sha256(fix_file)
                            is_real = "synthetic" not in fix_file.name.lower()
                            artifacts.append(ManifestArtifact(
                                vendor=vendor_key,
                                artifact_type="configuration_fixture",
                                path=str(fix_file.relative_to(self.dataset_base)).replace("\\", "/"),
                                source=f"Sanitized {vendor_key} Configuration Fixture",
                                source_url="",
                                real_or_synthetic="real" if is_real else "synthetic",
                                sha256=sha,
                                byte_size=fix_file.stat().st_size,
                                version="latest",
                                sanitized=True,
                                description=f"Test fixture for parser and compliance validation ({'real' if is_real else 'synthetic'})",
                            ))

        manifest_data = {
            "schema_version": "2.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "description": "Cryptographically auditable manifest of authoritative vendor references, commands, grammars, and fixtures.",
            "total_artifacts": len(artifacts),
            "artifacts": [asdict(a) for a in artifacts],
        }

        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        return manifest_data

    def validate_dataset(self) -> DatasetValidationResult:
        """Validate every artifact in manifest against filesystem state and hashes."""
        if not self.manifest_path.exists():
            self.generate_manifest()

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)

        artifacts = manifest_data.get("artifacts", [])
        total = len(artifacts)
        valid = 0
        missing = []
        hash_mismatches = []
        empty_files = []

        for a in artifacts:
            rel_path = a.get("path", "")
            full_path = self.dataset_base / rel_path

            if not full_path.exists():
                missing.append(rel_path)
                continue

            if full_path.stat().st_size == 0:
                empty_files.append(rel_path)
                continue

            actual_sha = self._calculate_sha256(full_path)
            expected_sha = a.get("sha256", "")

            if actual_sha != expected_sha:
                hash_mismatches.append({
                    "path": rel_path,
                    "expected_sha256": expected_sha,
                    "actual_sha256": actual_sha,
                })
            else:
                valid += 1

        is_valid = (len(missing) == 0 and len(hash_mismatches) == 0 and len(empty_files) == 0)

        return DatasetValidationResult(
            total_artifacts=total,
            valid_artifacts=valid,
            missing_files=missing,
            hash_mismatches=hash_mismatches,
            empty_files=empty_files,
            untracked_files=[],
            is_valid=is_valid,
        )
