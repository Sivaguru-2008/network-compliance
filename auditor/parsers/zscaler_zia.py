"""Deterministic Zscaler ZIA (Zscaler Internet Access) API configuration parser.

Validation Status: SYNTHETIC / CLOUD API FORMAT.
Zscaler ZIA is a 100% cloud-delivered SASE platform configured via Cloud Admin Portal
and REST API JSON (no on-box text running-config exists). This parser processes JSON API
responses and must not be categorized as on-premises production device grammar.
"""

import hashlib
import json
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class ZscalerZIAParser(VendorParser):
    """JSON-based parser for Zscaler ZIA API configuration responses."""

    name = "zscaler_zia"
    vendor = "zscaler"
    os_family = "zia"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        try:
            data = json.loads(config_text)
        except Exception:
            return 0.0
            
        if not isinstance(data, dict):
            return 0.0
            
        score = 0.0
        # ZIA-specific API response keys
        zia_keys = {"adminUsers", "nssFeeds", "securityPolicy", "samlAttributes", "zia_configuration"}
        matching_keys = zia_keys.intersection(data.keys())
        if matching_keys:
            score += 0.8
            for key in matching_keys:
                sub = data[key]
                if isinstance(sub, (list, dict)):
                    score += 0.2
        return min(1.0, score)

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        try:
            data = json.loads(config_text)
        except Exception as e:
            raise ParserError(f"Malformed JSON configuration: {e}") from e

        self._raw_lines = config_text.splitlines()
        
        baseline = SecurityBaselineModel(
            provenance=ParserProvenance(
                parser_name=self.name,
                parser_version=self.version,
                vendor=self.vendor,
                os_family=self.os_family,
                detection_confidence=self.detect(config_text),
            ),
            source_file=source_file,
            source_sha256=hashlib.sha256(config_text.encode("utf-8", errors="replace")).hexdigest(),
            config_line_count=len(self._raw_lines),
        )

        self._normalize_hostname(data, baseline)
        self._normalize_http_https(baseline)
        self._normalize_ssh_telnet(baseline)
        self._normalize_logging(data, baseline)

        # Set all remaining unparsed fields to unknown
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Zscaler ZIA parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, path: str, value: str) -> Tuple[str, int, str]:
        line_num = 1
        key_to_find = path.split("/")[-1]
        for idx, line in enumerate(self._raw_lines):
            if f'"{key_to_find}"' in line:
                line_num = idx + 1
                break
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"JSON Path: {path} -> {value}"

    def _normalize_hostname(self, data: dict, baseline: SecurityBaselineModel) -> None:
        tenant_name = None
        path = None
        
        # ZIA configuration tenant identification
        if "zia_configuration" in data and isinstance(data["zia_configuration"], dict):
            tenant_name = data["zia_configuration"].get("tenant")
            path = "/zia_configuration/tenant"
        elif "tenant" in data:
            tenant_name = data.get("tenant")
            path = "/tenant"

        if tenant_name and path:
            raw, line, note = self._evidence(path, tenant_name)
            baseline.hostname = Observation[str].found(tenant_name, raw, line, note=note)
        else:
            baseline.hostname = Observation[str].unknown("Zscaler ZIA tenant identification is not present.")

    def _normalize_http_https(self, baseline: SecurityBaselineModel) -> None:
        # ZIA Admin portal enforces HTTPS administration connections
        baseline.http_server_enabled = Observation[bool].absent(
            False, "Zscaler ZIA Admin Portal does not support HTTP cleartext administration."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            True, "Zscaler ZIA Admin Portal is strictly HTTPS-only."
        )

    def _normalize_ssh_telnet(self, baseline: SecurityBaselineModel) -> None:
        # Zscaler cloud architecture does not support SSH/Telnet administration access
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet access is unsupported in Zscaler ZIA."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            False, "SSH access is unsupported in Zscaler ZIA."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            [], "No VTY transports are supported in Zscaler ZIA."
        )
        baseline.ssh_version = Observation[int].absent(
            2, "SSH management is not applicable."
        )

    def _normalize_logging(self, data: dict, baseline: SecurityBaselineModel) -> None:
        # Check Nanolog Streaming Service (nssFeeds) configuration status
        nss_configured = False
        path = None

        if "nssFeeds" in data:
            if isinstance(data["nssFeeds"], list) and len(data["nssFeeds"]) > 0:
                nss_configured = True
                path = "/nssFeeds"
            elif isinstance(data["nssFeeds"], dict):
                nss_configured = True
                path = "/nssFeeds"

        if nss_configured and path:
            raw, line, note = self._evidence(path, "configured")
            baseline.logging_enabled = Observation[bool].found(True, raw, line, note=note)
            baseline.logging_hosts = Observation[List[str]].found(["Zscaler NSS Log Collector"], raw, line, note=note)
        else:
            baseline.logging_enabled = Observation[bool].unknown("Zscaler NSS feeds log status is unknown.")
            baseline.logging_hosts = Observation[List[str]].unknown("Zscaler NSS log hosts are unknown.")
