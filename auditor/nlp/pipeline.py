"""End-to-end NLP pipeline: natural-language requirement -> compliance control mapping.

Usage:
    from auditor.nlp import NLPPipeline
    pipeline = NLPPipeline()
    results = pipeline.process("Ensure SSH version 2 is enforced and disable telnet")
    for r in results:
        print(r.rule_ids, r.confidence, r.status)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .extractor import ExtractionResult, Intent, SecurityEntity, extract
from .mapper import MappingResult, MappingStatus, RuleMapping, map_requirement
from .preprocessor import PreprocessedText, preprocess, split_requirements


@dataclass
class RequirementResult:
    """Final output for one natural-language requirement."""

    source_text: str
    preprocessed_text: str
    intent: str
    is_negative: bool
    entities: List[Dict[str, Any]] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    rule_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    status: str = "UNKNOWN"
    mappings: List[Dict[str, Any]] = field(default_factory=list)
    vendor_terms_detected: List[str] = field(default_factory=list)
    synonyms_expanded: Dict[str, List[str]] = field(default_factory=dict)


class NLPPipeline:
    """Stateless pipeline converting natural-language requirements to rule mappings."""

    def __init__(self, confidence_threshold: float = 0.40):
        self.confidence_threshold = confidence_threshold

    def process(self, text: str) -> List[RequirementResult]:
        """Process one or more requirements from natural-language input.

        Returns one RequirementResult per detected sub-requirement.
        """
        if not text or not text.strip():
            return [RequirementResult(
                source_text=text or "",
                preprocessed_text="",
                intent="UNKNOWN",
                is_negative=False,
                status="UNKNOWN",
            )]

        parts = split_requirements(text)
        results = []
        for part in parts:
            result = self._process_single(part)
            results.append(result)
        return results

    def _process_single(self, text: str) -> RequirementResult:
        """Process a single requirement string."""
        preprocessed = preprocess(text)
        extraction = extract(preprocessed)
        mapping = map_requirement(extraction, expanded_text=preprocessed.normalized_expanded)

        entities_data = [
            {
                "concept": e.concept,
                "source_span": e.source_span,
                "parameters": e.parameters,
            }
            for e in mapping.entities
        ]
        mappings_data = [
            {
                "rule_id": m.rule_id,
                "title": m.title,
                "confidence": m.confidence,
                "status": m.status.value,
                "matched_concepts": m.matched_concepts,
            }
            for m in mapping.mappings
        ]

        rule_ids = mapping.mapped_rule_ids
        confidence = mapping.mappings[0].confidence if mapping.mappings else 0.0

        return RequirementResult(
            source_text=text,
            preprocessed_text=preprocessed.normalized,
            intent=extraction.intent.value,
            is_negative=extraction.is_negative_requirement,
            entities=entities_data,
            parameters=extraction.parameters,
            rule_ids=rule_ids,
            confidence=confidence,
            status=mapping.status.value,
            mappings=mappings_data,
            vendor_terms_detected=preprocessed.detected_vendor_terms,
            synonyms_expanded=preprocessed.expanded_synonyms,
        )

    def process_and_evaluate(
        self,
        text: str,
        baseline,
    ) -> List[Dict[str, Any]]:
        """Process requirements and evaluate matched rules against a parsed baseline.

        This connects NLP output to the existing compliance engine without duplicating it.
        Returns a list of dicts with the mapping result plus the compliance evaluation.
        """
        from ..engine.evaluator import ComplianceEngine
        from ..models.rule import ComplianceRule, RuleSet
        from ..rules.loader import load_framework

        results = self.process(text)
        output = []

        for req_result in results:
            entry: Dict[str, Any] = {
                "requirement": req_result.source_text,
                "nlp_result": req_result,
                "compliance_results": [],
            }

            if req_result.status != "MAPPED":
                output.append(entry)
                continue

            platform_key = (
                f"{baseline.provenance.vendor}_{baseline.provenance.os_family}"
            )
            try:
                ruleset = load_framework("CIS", platform_key, allow_cross_platform=True)
            except Exception:
                output.append(entry)
                continue

            engine = ComplianceEngine(ruleset)
            for rule_id in req_result.rule_ids:
                for rule in ruleset.rules:
                    ctrl = rule.internal_control_id or rule.id
                    if ctrl == rule_id or rule.id == rule_id:
                        cr = engine.evaluate_rule(rule, baseline)
                        entry["compliance_results"].append(cr)
                        break

            output.append(entry)

        return output
