"""Unit tests for QA Grounding and Balanced Polarities."""

import json
from pathlib import Path
import pytest
from nlp_pipeline.dataset_builder import NLPDatasetBuilder
from nlp_pipeline.extractor import SecuritySemanticExtractor

def test_qa_grounding_rejects_empty_context():
    """Verify that QA dataset generation enforces context presence."""
    cfg_text = "hostname R1\nline vty 0 4\n transport input ssh\n!"
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(cfg_text, file_id="test_qa_ground", vendor_slug="cisco_ios")
    raw_texts = {"test_qa_ground": cfg_text}

    builder = NLPDatasetBuilder()
    examples = builder._generate_task_d_qa([cfg], raw_texts)

    for ex in examples:
        assert "Context:" in ex["input"]
        ctx_part = ex["input"].split("Context:\n")[-1]
        assert len(ctx_part.strip()) > 0
        assert ex["output"] in ("yes", "no")
