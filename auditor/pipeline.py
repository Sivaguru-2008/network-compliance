"""The single-file audit, as callable stages rather than CLI-shaped code.

Every stage the CLI runs for one configuration lives here: select a parser,
parse to the baseline, evaluate the requested frameworks against that one
baseline, assemble the report.  The CLI calls these; so does the bulk ingestion
orchestrator.  That is the whole point -- bulk ingestion must be a loop over
the single-file path, and the only way to guarantee it stays one is for both
callers to run the same code rather than two copies that drift apart.

Two properties this module is responsible for keeping true:

* **Parse once, evaluate many.**  ``evaluate`` takes a baseline that has already
  been produced and runs every framework against it.  Adding a second framework
  costs one more rule-pack evaluation, never a second parse.
* **Framework neutrality.**  Nothing below knows what CIS or NIST *mean*.  A
  framework is a name that resolves to a rule pack; the pack is evaluated by the
  same engine, against the same vendor-neutral baseline, for all of them.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple, Type

from . import __version__
from .engine import ComplianceEngine
from .models.baseline import SecurityBaselineModel
from .models.result import (
    AuditReport,
    ControlResult,
    FrameworkInfo,
    ReportSummary,
    TargetInfo,
)
from .models.rule import RuleSet
from .parsers import HybridParser, LLMParser, VendorParser, registry
from .rules import load_framework, load_ruleset, platform_mismatch_note

TOOL_NAME = "netaudit"

#: Evaluated when the caller names no framework, matching the CLI's long-standing
#: default. Kept here so the bulk path and the single-file path cannot disagree.
DEFAULT_FRAMEWORK = "CIS"


@dataclass
class EvaluationOutcome:
    """Results of running one or more frameworks against a single baseline."""

    results: List[ControlResult] = field(default_factory=list)
    frameworks: List[FrameworkInfo] = field(default_factory=list)
    summaries: Dict[str, ReportSummary] = field(default_factory=dict)
    primary: Optional[FrameworkInfo] = None


class RulesetResolver:
    """Loads rule packs once per (framework, platform) within one caller's scope.

    A 200-device batch against four frameworks would otherwise re-read the same
    rule JSON eight hundred times. The cache is deliberately an *object* rather
    than a module-level memo: a batch owns one, it dies with the batch, and no
    state carries from one run into the next. Rule packs are only read from here,
    never written, so devices sharing one are isolated in every way that matters.
    """

    def __init__(self) -> None:
        self._packs: Dict[Tuple[str, str], RuleSet] = {}

    def framework(self, name: str, platform_key: str) -> RuleSet:
        key = (name, platform_key)
        if key not in self._packs:
            self._packs[key] = load_framework(name, platform_key, allow_cross_platform=True)
        return self._packs[key]

    def explicit(self, rules_path) -> RuleSet:
        key = ("", str(rules_path))
        if key not in self._packs:
            self._packs[key] = load_ruleset(rules_path)
        return self._packs[key]


def select_parser(
    config_text: str,
    vendor: Optional[str] = None,
    allow_llm: bool = False,
) -> Tuple[Type[VendorParser], float]:
    """Explicit ``vendor`` wins; otherwise rank the registered parsers.

    Raises ``ParserError`` when nothing clears the detection threshold -- which
    is the signal a caller uses to record a device as ``unknown_vendor`` rather
    than guessing at one.
    """
    if vendor:
        parser_cls = registry.get(vendor)
        return parser_cls, parser_cls.detect(config_text)
    return registry.detect(config_text, allow_fallback=allow_llm)


def parse_config(
    parser: VendorParser,
    config_text: str,
    *,
    source_file: Optional[str] = None,
    parser_cls: Optional[Type[VendorParser]] = None,
    confidence: Optional[float] = None,
) -> SecurityBaselineModel:
    """Run one parser over one configuration, recording the detection score.

    The score is only stamped on for deterministic parsers. The LLM parser
    reports the vendor it identified from the text itself, and the hybrid parser
    carries the confidence of the deterministic parser it built on; neither is
    improved by the registry's score for the class.
    """
    baseline = parser.parse(config_text, source_file=source_file)
    if confidence is not None and parser_cls not in (LLMParser, HybridParser):
        baseline.provenance.detection_confidence = confidence
    return baseline


def platform_key_for(baseline: SecurityBaselineModel) -> str:
    """Platform comes from the parsed baseline, not the parser class.

    The LLM fallback only learns the vendor by reading the configuration, so
    asking the baseline is the one answer that is right for every parser.
    """
    return f"{baseline.provenance.vendor}_{baseline.provenance.os_family}"


def evaluate(
    baseline: SecurityBaselineModel,
    frameworks: Sequence[str],
    *,
    rules_path=None,
    resolver: Optional[RulesetResolver] = None,
) -> EvaluationOutcome:
    """Evaluate every requested framework against one already-parsed baseline.

    ``resolver`` lets a batch share loaded rule packs across its devices. Omit it
    and this call gets a private one, which is exactly the single-file behaviour.
    """
    outcome = EvaluationOutcome()
    platform_key = platform_key_for(baseline)
    resolver = resolver or RulesetResolver()

    if rules_path:
        rulesets = [resolver.explicit(rules_path)]
    else:
        rulesets = [resolver.framework(name, platform_key) for name in frameworks]

    for ruleset in rulesets:
        results = ComplianceEngine(ruleset).evaluate(baseline)
        outcome.results.extend(results)
        info = FrameworkInfo(
            name=ruleset.framework,
            version=ruleset.framework_version,
            rules_evaluated=len(results),
            source_note=ruleset.source_note,
            platform_note=platform_mismatch_note(
                ruleset, baseline.provenance.vendor, baseline.provenance.os_family
            ),
        )
        outcome.frameworks.append(info)
        outcome.summaries[ruleset.framework] = ReportSummary.from_results(results)
        if outcome.primary is None:
            outcome.primary = info

    return outcome


def target_info(baseline: SecurityBaselineModel) -> TargetInfo:
    """What was audited and how it was read -- shared by the report and by inventory."""
    return TargetInfo(
        source_file=baseline.source_file,
        source_sha256=baseline.source_sha256,
        hostname=baseline.hostname.value,
        vendor=baseline.provenance.vendor,
        os_family=baseline.provenance.os_family,
        parser=baseline.provenance.parser_name,
        parser_version=baseline.provenance.parser_version,
        detection_confidence=baseline.provenance.detection_confidence,
        config_line_count=baseline.config_line_count,
        parser_warnings=baseline.provenance.warnings,
    )


def build_report(
    baseline: SecurityBaselineModel,
    outcome: EvaluationOutcome,
    *,
    include_baseline: bool = True,
) -> AuditReport:
    """Assemble the structured deliverable the table and the JSON both render."""
    return AuditReport(
        tool={"name": TOOL_NAME, "version": __version__},
        target=target_info(baseline),
        framework=outcome.primary,
        frameworks=outcome.frameworks,
        framework_summaries=outcome.summaries,
        summary=ReportSummary.from_results(outcome.results),
        results=outcome.results,
        baseline=baseline if include_baseline else None,
    )


def audit_baseline(
    baseline: SecurityBaselineModel,
    frameworks: Sequence[str],
    *,
    rules_path=None,
    include_baseline: bool = True,
    resolver: Optional[RulesetResolver] = None,
) -> AuditReport:
    """Evaluate then assemble: the second half of a single-file audit."""
    outcome = evaluate(baseline, frameworks, rules_path=rules_path, resolver=resolver)
    return build_report(baseline, outcome, include_baseline=include_baseline)


def audit_unknown_vendor_offline(
    config_text: str,
    source_file: str,
    frameworks: Sequence[str],
    *,
    error_msg: str,
    include_baseline: bool = True,
) -> AuditReport:
    """Produce an AuditReport for an unknown/unsupported vendor when offline.
    
    All controls for the requested frameworks will be reported as NEEDS_REVIEW.
    """
    import hashlib
    from .models.baseline import ParserProvenance, SecurityBaselineModel
    from .models.result import AuditReport, ControlResult, FrameworkInfo, ReportSummary, TargetInfo, Status
    from .models.rule import Severity, Remediation
    from .knowledge.bootstrap import bootstrap_database_if_empty
    from .knowledge.repository import get_db_connection
    import json
    
    bootstrap_database_if_empty()
    
    source_sha256 = hashlib.sha256(config_text.encode("utf-8", errors="replace")).hexdigest()
    config_line_count = len(config_text.splitlines())
    
    # Construct a dummy baseline
    baseline = SecurityBaselineModel(
        source_file=source_file,
        source_sha256=source_sha256,
        config_line_count=config_line_count,
        provenance=ParserProvenance(
            parser_name="unknown",
            parser_version="0.0.0",
            vendor="unknown",
            os_family="unknown",
            detection_confidence=0.0,
            warnings=[error_msg]
        )
    )
    
    results = []
    framework_infos = []
    summaries = {}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for fw in frameworks:
        if ":" in fw:
            fw_name, fw_ver = fw.split(":", 1)
        else:
            fw_name = fw
            fw_ver = None
            
        # Query controls for this framework in knowledge.db
        query = """
        SELECT DISTINCT control_id, title, description, severity, source_location, framework_display_name, framework_version, references_json
        FROM controls
        WHERE LOWER(framework) = LOWER(?)
        """
        params = [fw_name]
        if fw_ver:
            query += " AND framework_version = ?"
            params.append(fw_ver)
            
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        fw_disp = fw_name
        actual_ver = fw_ver or "1.0"
        
        fw_results = []
        for row in rows:
            fw_disp = row["framework_display_name"] or fw_name
            actual_ver = row["framework_version"]
            
            # Create a NEEDS_REVIEW result
            res = ControlResult(
                rule_id=row["control_id"],
                control_id=row["control_id"],
                control_ref=row["source_location"],
                title=row["title"],
                description=row["description"] or "",
                framework=fw_disp,
                severity=Severity(row["severity"].lower()),
                status=Status.NEEDS_REVIEW,
                message=f"Unsupported vendor configuration offline. Manual review required. (Parser error: {error_msg})",
                evidence=[],
                remediation=Remediation(summary="Verify configuration settings manually for this device.", cli=[]),
                references=json.loads(row["references_json"]) if row["references_json"] else [],
                device=baseline.hostname.value or source_file,
                vendor="unknown",
                parser="unknown",
                knowledge_version=actual_ver,
                source_reference=row["source_location"],
                evaluation_result=Status.NEEDS_REVIEW.value,
                reason=f"Unsupported vendor configuration offline. Manual review required. (Parser error: {error_msg})"
            )
            fw_results.append(res)
            
        results.extend(fw_results)
        
        fw_info = FrameworkInfo(
            name=fw_disp,
            version=actual_ver,
            rules_evaluated=len(fw_results),
            source_note="No platform-specific rule mappings loaded due to unknown vendor."
        )
        framework_infos.append(fw_info)
        summaries[fw_disp] = ReportSummary.from_results(fw_results)
        
    conn.close()
    
    return AuditReport(
        tool={"name": TOOL_NAME, "version": __version__},
        target=target_info(baseline),
        framework=framework_infos[0] if framework_infos else None,
        frameworks=framework_infos,
        framework_summaries=summaries,
        summary=ReportSummary.from_results(results),
        results=results,
        baseline=baseline if include_baseline else None
    )
