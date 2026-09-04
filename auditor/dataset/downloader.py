"""Authoritative vendor reference downloader and web crawler."""

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

from .sources import AccessType, DocumentFormat, VendorSource, get_all_vendor_keys, get_sources_for_vendor

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 (NetworkComplianceAuditor/1.0)"

LOGIN_INDICATORS = [
    "login.cisco.com",
    "signin.arista.com",
    "uniportal.huawei.com",
    "login to download",
    "sign in to access",
    "authentication required",
    "create an account to view",
    "unauthorized access",
    "please log in",
    "enter your credentials",
]


@dataclass
class DownloadResult:
    vendor_key: str
    source_url: str
    local_path: Optional[str]
    metadata_path: Optional[str]
    sha256: Optional[str]
    byte_size: int
    retrieved_at: str
    status: str  # "DOWNLOADED", "CACHED", "ACCESS_REQUIRES_ACCOUNT", "UNAVAILABLE", "FAILED", "INVALID_CONTENT"
    source_type: str = "OFFICIAL_VENDOR_DOCUMENTATION"
    document_title: str = ""
    version: str = ""
    error_message: Optional[str] = None
    access_type: str = "open"


class ReferenceDownloader:
    """Downloader that fetches authoritative vendor documentation and records auditable provenance."""

    def __init__(self, dataset_base: Path = Path("dataset")):
        self.dataset_base = Path(dataset_base)
        self.vendor_ref_base = self.dataset_base / "vendor_references"
        self.client = httpx.Client(
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            timeout=30.0,
            follow_redirects=True,
            verify=True,
        )

    def _ensure_vendor_dirs(self, vendor_key: str) -> Dict[str, Path]:
        vendor_dir = self.vendor_ref_base / vendor_key
        subdirs = {
            "documents": vendor_dir / "documents",
            "raw": vendor_dir / "raw",
            "extracted": vendor_dir / "extracted",
            "commands": vendor_dir / "commands",
            "schemas": vendor_dir / "schemas",
            "config_fixtures": vendor_dir / "config_fixtures",
            "metadata": vendor_dir / "metadata",
        }
        for path in subdirs.values():
            path.mkdir(parents=True, exist_ok=True)
        return subdirs

    def _calculate_sha256(self, content: bytes) -> str:
        hasher = hashlib.sha256()
        hasher.update(content)
        return hasher.hexdigest()

    def _is_login_page(self, content_text: str, final_url: str) -> bool:
        lower_url = str(final_url).lower()
        lower_content = content_text.lower()
        for ind in LOGIN_INDICATORS:
            if ind in lower_url or ind in lower_content:
                return True
        return False

    def download_source(
        self,
        source: VendorSource,
        force: bool = False,
        retries: int = 3,
        backoff_factor: float = 1.5,
    ) -> DownloadResult:
        """Download a single vendor reference source and store with cryptographic metadata."""
        dirs = self._ensure_vendor_dirs(source.vendor_key)
        target_filename = source.target_filename or (source.doc_title.lower().replace(" ", "_") + f".{source.doc_format.value}")
        target_path = dirs["documents"] / target_filename
        meta_path = dirs["metadata"] / f"{Path(target_filename).stem}.meta.json"
        retrieved_at = datetime.now(timezone.utc).isoformat()

        # Check if already downloaded and verified (caching)
        if not force and target_path.exists() and meta_path.exists():
            try:
                content = target_path.read_bytes()
                file_sha = self._calculate_sha256(content)
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                if meta.get("sha256") == file_sha:
                    return DownloadResult(
                        vendor_key=source.vendor_key,
                        source_url=source.url,
                        local_path=str(target_path.relative_to(self.dataset_base)),
                        metadata_path=str(meta_path.relative_to(self.dataset_base)),
                        sha256=file_sha,
                        byte_size=len(content),
                        retrieved_at=meta.get("retrieved_at", retrieved_at),
                        status="CACHED",
                        document_title=source.doc_title,
                        version=source.version,
                        access_type=source.access_type.value,
                    )
            except Exception as e:
                logger.warning("Cache validation error for %s: %s", target_path, e)

        # Attempt to fetch content from URL
        attempt = 0
        last_error = None
        urls_to_try = [source.url] + source.backup_urls

        for current_url in urls_to_try:
            attempt = 0
            while attempt < retries:
                attempt += 1
                try:
                    time.sleep(0.5)  # Rate limiting
                    response = self.client.get(current_url)

                    # Handle access restriction or login requirement
                    if response.status_code in (401, 403):
                        logger.info("Access requires credentials for %s (Status %d)", current_url, response.status_code)
                        return self._record_metadata(
                            source=source,
                            status="ACCESS_REQUIRES_ACCOUNT",
                            target_path=None,
                            meta_path=meta_path,
                            content=b"",
                            retrieved_at=retrieved_at,
                            error_message=f"HTTP {response.status_code} Access Denied / Login Required",
                        )

                    if response.status_code == 404:
                        last_error = f"HTTP 404 Not Found: {current_url}"
                        break  # Try backup URL

                    response.raise_for_status()
                    content = response.content
                    final_url = str(response.url)

                    # Content validation
                    content_type = response.headers.get("content-type", "").lower()
                    if source.doc_format == DocumentFormat.PDF:
                        if not content.startswith(b"%PDF-"):
                            # Check if it returned a login page instead of a PDF
                            text_snippet = content[:2000].decode("utf-8", errors="ignore")
                            if self._is_login_page(text_snippet, final_url):
                                return self._record_metadata(
                                    source=source,
                                    status="ACCESS_REQUIRES_ACCOUNT",
                                    target_path=None,
                                    meta_path=meta_path,
                                    content=b"",
                                    retrieved_at=retrieved_at,
                                    error_message="Received HTML login prompt instead of PDF",
                                )
                            last_error = f"Invalid PDF header received for {current_url}"
                            break

                    elif source.doc_format in (DocumentFormat.HTML, DocumentFormat.MARKDOWN):
                        text_sample = content[:4000].decode("utf-8", errors="ignore")
                        if self._is_login_page(text_sample, final_url):
                            return self._record_metadata(
                                source=source,
                                status="ACCESS_REQUIRES_ACCOUNT",
                                target_path=None,
                                meta_path=meta_path,
                                content=b"",
                                retrieved_at=retrieved_at,
                                error_message="Received login gate page",
                            )

                    # Successfully retrieved valid content
                    target_path.write_bytes(content)
                    raw_backup = dirs["raw"] / target_filename
                    raw_backup.write_bytes(content)

                    return self._record_metadata(
                        source=source,
                        status="DOWNLOADED",
                        target_path=target_path,
                        meta_path=meta_path,
                        content=content,
                        retrieved_at=retrieved_at,
                    )

                except httpx.HTTPError as e:
                    last_error = str(e)
                    time.sleep(backoff_factor * attempt)
                except Exception as e:
                    last_error = str(e)
                    time.sleep(backoff_factor * attempt)

        # If we reached here, download failed across all URLs
        status = "ACCESS_REQUIRES_ACCOUNT" if source.access_type == AccessType.ACCESS_REQUIRES_ACCOUNT else "UNAVAILABLE"
        return self._record_metadata(
            source=source,
            status=status,
            target_path=None,
            meta_path=meta_path,
            content=b"",
            retrieved_at=retrieved_at,
            error_message=last_error or "Unable to retrieve document",
        )

    def _record_metadata(
        self,
        source: VendorSource,
        status: str,
        target_path: Optional[Path],
        meta_path: Path,
        content: bytes,
        retrieved_at: str,
        error_message: Optional[str] = None,
    ) -> DownloadResult:
        sha256 = self._calculate_sha256(content) if content else None
        local_rel = str(target_path.relative_to(self.dataset_base)) if target_path else None
        meta_rel = str(meta_path.relative_to(self.dataset_base))

        meta_dict = {
            "vendor": source.vendor_key,
            "vendor_name": source.vendor_name,
            "os_name": source.os_name,
            "config_format": source.config_format,
            "document_title": source.doc_title,
            "source_url": source.url,
            "source_type": "OFFICIAL_VENDOR_DOCUMENTATION",
            "access_type": source.access_type.value,
            "doc_format": source.doc_format.value,
            "version": source.version,
            "retrieved_at": retrieved_at,
            "status": status,
            "sha256": sha256,
            "byte_size": len(content),
            "local_path": local_rel,
            "license_or_access_note": "Authoritative vendor technical documentation acquired for parser & compliance syntax validation.",
            "error_message": error_message,
        }

        meta_path.parent.mkdir(parents=True, exist_ok=True)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_dict, f, indent=2)

        return DownloadResult(
            vendor_key=source.vendor_key,
            source_url=source.url,
            local_path=local_rel,
            metadata_path=meta_rel,
            sha256=sha256,
            byte_size=len(content),
            retrieved_at=retrieved_at,
            status=status,
            source_type="OFFICIAL_VENDOR_DOCUMENTATION",
            document_title=source.doc_title,
            version=source.version,
            error_message=error_message,
            access_type=source.access_type.value,
        )

    def download_all(self, vendor: str = "all", force: bool = False) -> List[DownloadResult]:
        """Download all sources for a specific vendor or all vendors."""
        sources = get_sources_for_vendor(vendor)
        results = []
        for src in sources:
            res = self.download_source(src, force=force)
            results.append(res)
        return results
