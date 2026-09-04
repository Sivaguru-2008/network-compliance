"""Deterministic Cato Networks API configuration parser.

Validation Status: SYNTHETIC / CLOUD API FORMAT.
Cato Networks is a 100% cloud-native SASE platform configured via Cato Cloud Management
and GraphQL API (no on-box text running-config exists). This parser processes GraphQL API
JSON responses and must not be claimed as on-premises production device grammar.
"""

import hashlib
import json
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class CatoNetworksParser(VendorParser):
    """JSON-based parser for Cato Networks GraphQL API configuration responses."""

    name = "cato_networks"
    vendor = "cato"
    os_family = "cato_networks"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        # Validate that the file is well-formed JSON
        try:
            data = json.loads(config_text)
        except Exception:
            return 0.0
            
        if not isinstance(data, dict):
            return 0.0
            
        # Check for Cato-specific GraphQL response structure
        score = 0.0
        if "data" in data and isinstance(data["data"], dict):
            cato_queries = {"accountBySubdomain", "auditFeed", "entityLookup", "accountMetrics", "cato_configuration"}
            matching_keys = cato_queries.intersection(data["data"].keys())
            if matching_keys:
                score += 0.8
                # Add score for specific nested fields
                for key in matching_keys:
                    sub = data["data"][key]
                    if isinstance(sub, dict):
                        if "entities" in sub or "marker" in sub or "subdomain" in sub or "id" in sub:
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
                        "Cato Networks parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, path: str, value: str) -> Tuple[str, int, str]:
        # Search the lines of JSON to find the key
        line_num = 1
        key_to_find = path.split("/")[-1]
        for idx, line in enumerate(self._raw_lines):
            if f'"{key_to_find}"' in line:
                line_num = idx + 1
                break
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"JSON Path: {path} -> {value}"

    def _normalize_hostname(self, data: dict, baseline: SecurityBaselineModel) -> None:
        # Extract account name or subdomain
        subdomain = None
        path = None
        
        if "data" in data and isinstance(data["data"], dict):
            acc = data["data"].get("accountBySubdomain")
            if isinstance(acc, dict) and acc.get("name"):
                subdomain = acc.get("name")
                path = "/data/accountBySubdomain/name"
            elif isinstance(acc, dict) and acc.get("subdomain"):
                subdomain = acc.get("subdomain")
                path = "/data/accountBySubdomain/subdomain"

        if subdomain and path:
            raw, line, note = self._evidence(path, subdomain)
            baseline.hostname = Observation[str].found(subdomain, raw, line, note=note)
        else:
            baseline.hostname = Observation[str].unknown(
                "Cato account subdomain or name is not present in this API JSON response."
            )

    def _normalize_http_https(self, baseline: SecurityBaselineModel) -> None:
        # Cato Management Application only supports secure HTTPS administrative connections
        baseline.http_server_enabled = Observation[bool].absent(
            False, "Cato SASE cloud administration does not support unencrypted HTTP."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            True, "Cato SASE cloud administration is strictly HTTPS-only."
        )

    def _normalize_ssh_telnet(self, baseline: SecurityBaselineModel) -> None:
        # Cato Networks cloud endpoints do not support Telnet/SSH management access
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet administrative management is not supported by Cato SASE Cloud."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            False, "SSH administrative management is not supported by Cato SASE Cloud."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            [], "No VTY transports are supported in Cato SASE Cloud."
        )
        baseline.ssh_version = Observation[int].absent(
            2, "SSH management is not supported or applicable."
        )

    def _normalize_logging(self, data: dict, baseline: SecurityBaselineModel) -> None:
        # Verify if auditFeed is configured in the API response JSON
        has_audit_feed = False
        path = None

        if "data" in data and isinstance(data["data"], dict):
            feed = data["data"].get("auditFeed")
            if isinstance(feed, dict):
                has_audit_feed = True
                path = "/data/auditFeed"

        if has_audit_feed and path:
            raw, line, note = self._evidence(path, "configured")
            baseline.logging_enabled = Observation[bool].found(True, raw, line, note=note)
            baseline.logging_hosts = Observation[List[str]].found(["Cato SASE Log Cloud Engine"], raw, line, note=note)
        else:
            baseline.logging_enabled = Observation[bool].unknown(
                "Cato audit log feed status is not present in this API JSON response."
            )
            baseline.logging_hosts = Observation[List[str]].unknown(
                "Cato syslog/event forwarders are not present in this API JSON response."
            )
