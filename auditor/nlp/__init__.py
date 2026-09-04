"""NLP requirement-to-rule mapping pipeline.

Converts natural-language security/compliance requirements into machine-actionable
compliance controls that the existing ComplianceEngine can evaluate.
"""

from .pipeline import NLPPipeline, RequirementResult

__all__ = ["NLPPipeline", "RequirementResult"]
