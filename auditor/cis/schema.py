"""Normalized schema for CIS benchmark recommendations extracted from PDFs."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AssessmentStatus(str, Enum):
    AUTOMATED = "Automated"
    MANUAL = "Manual"


class Profile(str, Enum):
    LEVEL_1 = "Level 1"
    LEVEL_2 = "Level 2"


class EvaluationType(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    PARSER_REQUIRED = "PARSER_REQUIRED"
    SEMANTIC = "SEMANTIC"
    MANUAL = "MANUAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SourceProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    file: str
    hash: str
    page: int
    benchmark_id: str
    benchmark_version: str


class CISRecommendation(BaseModel):
    """One CIS benchmark recommendation extracted from a PDF."""

    framework: str = "CIS"
    benchmark_id: str
    vendor: str
    product: str
    benchmark_version: str
    rule_id: str = Field(description="CIS recommendation number, e.g. '2.1.1'")
    title: str
    assessment_status: AssessmentStatus
    profile: List[Profile]
    description: str
    rationale: str = ""
    impact: str = ""
    audit: str = ""
    remediation: str = ""
    default_value: str = ""
    references: List[str] = Field(default_factory=list)
    cis_controls: str = ""
    additional_info: str = ""
    section: str = ""
    source: SourceProvenance
    evaluation_type: EvaluationType = EvaluationType.MANUAL


class CISBenchmark(BaseModel):
    """A complete extracted CIS benchmark."""

    benchmark_id: str
    framework: str = "CIS"
    vendor: str
    product: str
    product_version: str
    benchmark_version: str
    publication_date: str
    source_file: str
    source_hash: str
    pages: int
    profiles: List[str]
    sections: List[str]
    recommendations: List[CISRecommendation]
    extraction_warnings: List[str] = Field(default_factory=list)
