"""Comprehensive tests for the NLP semantic generalization pipeline.

Covers: training pipeline, model loading, deterministic reproducibility,
label encoding, normalization, value extraction, unknown detection,
confidence thresholds, ambiguous detection, hard negatives, comments,
malformed configurations, cross-vendor evaluation, file-level leakage,
human approval/rejection, learned mappings, AI cannot produce PASS/FAIL,
parser isolation, and existing vendor isolation.
"""

import json
import tempfile
from pathlib import Path
from typing import List

import pytest

from auditor.training.nlp_pipeline import (
    AMBIGUOUS_LABEL,
    CONCEPT_TO_FIELD,
    FIELD_TO_CONCEPT,
    NON_SECURITY_LABEL,
    ConfidencePolicy,
    NLPExample,
    NLPMetrics,
    NLPPrediction,
    SecurityConceptClassifier,
    _extract_value,
    apply_confidence_policy,
    dataset_stats,
    deterministic_predict,
    evaluate,
    evaluate_deterministic,
    evaluate_hard_negatives,
    evaluate_hybrid,
    generate_hard_negatives,
    hybrid_predict,
    load_split,
    preprocess_text,
    simulate_human_loop,
    tune_thresholds,
    vendor_held_out_evaluate,
    verify_no_leakage,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DATASET_DIR = Path(__file__).resolve().parent.parent.parent / "dataset" / "public_config"


def _make_examples() -> List[NLPExample]:
    return [
        NLPExample(raw_text="snmp-server community public RO",
                   vendor="Cisco", security_concept="SNMP Community Access",
                   normalized_field="snmp_communities", value=[{"name": "public", "access": "ro"}],
                   status="MAPPED", source_file="Cisco/snmp.conf", source_line=1),
        NLPExample(raw_text="snmp-server enable",
                   vendor="Cisco", security_concept="SNMP Agent Activation",
                   normalized_field="snmp_agent_enabled", value=True,
                   status="MAPPED", source_file="Cisco/snmp.conf", source_line=2),
        NLPExample(raw_text="exec-timeout 5 0",
                   vendor="Cisco", security_concept="Session Idle Inactivity Timeout",
                   normalized_field="vty_exec_timeout_seconds", value=300,
                   status="MAPPED", source_file="Cisco/vty.conf", source_line=1),
        NLPExample(raw_text="router bgp 65000",
                   vendor="Cisco", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None,
                   status="UNMAPPED", source_file="Cisco/bgp.conf", source_line=1),
        NLPExample(raw_text="neighbor 10.0.0.1 remote-as 65001",
                   vendor="Cisco", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None,
                   status="UNMAPPED", source_file="Cisco/bgp.conf", source_line=2),
        NLPExample(raw_text="interface GigabitEthernet0/0",
                   vendor="Cisco", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None,
                   status="UNMAPPED", source_file="Cisco/intf.conf", source_line=1),
        NLPExample(raw_text="ip flow-export source Loopback0",
                   vendor="Cisco", security_concept=AMBIGUOUS_LABEL,
                   normalized_field=None, value=None,
                   status="AMBIGUOUS", source_file="Cisco/flow.conf", source_line=1),
        NLPExample(raw_text="set snmp community mycomm authorization read-only",
                   vendor="Juniper", security_concept="SNMP Community Access",
                   normalized_field="snmp_communities", value=[{"name": "mycomm", "access": "ro"}],
                   status="MAPPED", source_file="Juniper/snmp.conf", source_line=1),
        NLPExample(raw_text="ip route 0.0.0.0 0.0.0.0 10.0.0.1",
                   vendor="Cisco", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None,
                   status="UNMAPPED", source_file="Cisco/routes.conf", source_line=1),
        NLPExample(raw_text="set system host-name router1",
                   vendor="Juniper", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None,
                   status="UNMAPPED", source_file="Juniper/system.conf", source_line=1),
    ]


@pytest.fixture
def examples():
    return _make_examples()


@pytest.fixture
def trained_classifier(examples):
    clf = SecurityConceptClassifier(random_seed=42)
    texts = [e.raw_text for e in examples]
    labels = [e.security_concept for e in examples]
    clf.fit(texts, labels)
    return clf


@pytest.fixture
def policy():
    return ConfidencePolicy(high_threshold=0.7, medium_threshold=0.4, low_threshold=0.2)


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------

class TestTrainingPipeline:
    def test_fit_produces_model(self, examples):
        clf = SecurityConceptClassifier(random_seed=42)
        clf.fit([e.raw_text for e in examples], [e.security_concept for e in examples])
        assert clf.pipeline is not None
        assert clf.classes_ is not None
        assert len(clf.classes_) > 0

    def test_fit_records_metadata(self, trained_classifier):
        meta = trained_classifier.training_metadata
        assert meta["n_samples"] == 10
        assert meta["n_classes"] > 0
        assert "class_distribution" in meta

    def test_predict_returns_predictions(self, trained_classifier):
        preds = trained_classifier.predict(["snmp-server community test RO"])
        assert len(preds) == 1
        assert isinstance(preds[0], NLPPrediction)
        assert preds[0].confidence > 0.0
        assert len(preds[0].top_3) <= 3

    def test_predict_one(self, trained_classifier):
        pred = trained_classifier.predict_one("router bgp 65000")
        assert isinstance(pred, NLPPrediction)


# ---------------------------------------------------------------------------
# Model loading and saving
# ---------------------------------------------------------------------------

class TestModelPersistence:
    def test_save_and_load(self, trained_classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir) / "model"
            trained_classifier.save(model_dir)

            assert (model_dir / "concept_classifier.joblib").is_file()
            assert (model_dir / "label_encoder.joblib").is_file()
            assert (model_dir / "training_metadata.json").is_file()

            loaded = SecurityConceptClassifier.load(model_dir)
            assert loaded.pipeline is not None
            assert list(loaded.classes_) == list(trained_classifier.classes_)

    def test_loaded_model_produces_same_predictions(self, trained_classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = Path(tmpdir) / "model"
            trained_classifier.save(model_dir)
            loaded = SecurityConceptClassifier.load(model_dir)

            texts = ["snmp-server community test RO", "router bgp 65000"]
            orig = trained_classifier.predict(texts)
            reloaded = loaded.predict(texts)

            for o, r in zip(orig, reloaded):
                assert o.predicted_concept == r.predicted_concept
                assert abs(o.confidence - r.confidence) < 1e-6


# ---------------------------------------------------------------------------
# Deterministic reproducibility
# ---------------------------------------------------------------------------

class TestReproducibility:
    def test_same_seed_same_model(self, examples):
        texts = [e.raw_text for e in examples]
        labels = [e.security_concept for e in examples]

        clf1 = SecurityConceptClassifier(random_seed=42)
        clf1.fit(texts, labels)
        clf2 = SecurityConceptClassifier(random_seed=42)
        clf2.fit(texts, labels)

        test_texts = ["snmp-server community test RO", "router bgp 65000", "exec-timeout 10"]
        preds1 = clf1.predict(test_texts)
        preds2 = clf2.predict(test_texts)

        for p1, p2 in zip(preds1, preds2):
            assert p1.predicted_concept == p2.predicted_concept
            assert abs(p1.confidence - p2.confidence) < 1e-10


# ---------------------------------------------------------------------------
# Label encoding
# ---------------------------------------------------------------------------

class TestLabelEncoding:
    def test_all_labels_encoded(self, trained_classifier):
        expected = {NON_SECURITY_LABEL, AMBIGUOUS_LABEL, "SNMP Community Access",
                    "SNMP Agent Activation", "Session Idle Inactivity Timeout"}
        actual = set(trained_classifier.classes_)
        assert expected == actual

    def test_concept_to_field_mapping(self):
        assert CONCEPT_TO_FIELD["SNMP Community Access"] == "snmp_communities"
        assert CONCEPT_TO_FIELD["SNMP Agent Activation"] == "snmp_agent_enabled"
        assert CONCEPT_TO_FIELD["Session Idle Inactivity Timeout"] == "vty_exec_timeout_seconds"

    def test_field_to_concept_inverse(self):
        for concept, field in CONCEPT_TO_FIELD.items():
            assert FIELD_TO_CONCEPT[field] == concept


# ---------------------------------------------------------------------------
# Text preprocessing / normalization
# ---------------------------------------------------------------------------

class TestPreprocessing:
    def test_lowercases(self):
        assert preprocess_text("SNMP-SERVER COMMUNITY") == "snmp-server community"

    def test_template_replacement(self):
        result = preprocess_text("ntp server {{ntp_ip}}")
        assert "<TEMPLATE>" in result
        assert "{{" not in result

    def test_ip_replacement(self):
        result = preprocess_text("logging host 10.0.0.1")
        assert "<IP>" in result
        assert "10.0.0.1" not in result

    def test_strips(self):
        assert preprocess_text("  ssh version 2  ") == "ssh version 2"


# ---------------------------------------------------------------------------
# Value extraction
# ---------------------------------------------------------------------------

class TestValueExtraction:
    def test_snmp_enabled_true(self):
        assert _extract_value("snmp-server enable", "snmp_agent_enabled") is True

    def test_snmp_enabled_false(self):
        assert _extract_value("no snmp-server", "snmp_agent_enabled") is False

    def test_snmp_community(self):
        val = _extract_value("snmp-server community public RO", "snmp_communities")
        assert isinstance(val, list)
        assert val[0]["name"] == "public"
        assert val[0]["access"] == "ro"

    def test_snmp_community_rw(self):
        val = _extract_value("snmp-server community private RW", "snmp_communities")
        assert val[0]["access"] == "rw"

    def test_timeout(self):
        assert _extract_value("exec-timeout 5 0", "vty_exec_timeout_seconds") == 0

    def test_timeout_single(self):
        assert _extract_value("exec-timeout 5", "vty_exec_timeout_seconds") == 5

    def test_ssh_enabled(self):
        assert _extract_value("transport input ssh", "ssh_enabled") is True

    def test_ssh_version(self):
        assert _extract_value("ip ssh version 2", "ssh_version") == "2"

    def test_logging_hosts(self):
        val = _extract_value("logging host 10.0.0.1", "logging_hosts")
        assert val == ["10.0.0.1"]

    def test_unknown_field(self):
        assert _extract_value("something", None) is None


# ---------------------------------------------------------------------------
# Unknown detection
# ---------------------------------------------------------------------------

class TestUnknownDetection:
    def test_non_security_classified(self, trained_classifier):
        pred = trained_classifier.predict_one("router ospf 1")
        assert pred.confidence > 0.0

    def test_unknown_flagged_by_policy(self, trained_classifier, policy):
        pred = trained_classifier.predict_one("xyzzy foobarbaz 12345")
        preds = apply_confidence_policy([pred], policy)
        # Low confidence → unknown/needs_review
        if preds[0].confidence < policy.medium_threshold:
            assert preds[0].is_unknown is True

    def test_deterministic_returns_non_security_for_unknown(self):
        pred = deterministic_predict("xyzzy foobarbaz 12345")
        assert pred.predicted_concept == NON_SECURITY_LABEL
        assert pred.is_unknown is True


# ---------------------------------------------------------------------------
# Confidence threshold
# ---------------------------------------------------------------------------

class TestConfidenceThreshold:
    def test_high_confidence(self):
        policy = ConfidencePolicy(high_threshold=0.7, medium_threshold=0.4, low_threshold=0.2)
        assert policy.classify_confidence(0.8) == "HIGH"
        assert policy.classify_confidence(0.7) == "HIGH"

    def test_medium_confidence(self):
        policy = ConfidencePolicy(high_threshold=0.7, medium_threshold=0.4, low_threshold=0.2)
        assert policy.classify_confidence(0.5) == "MEDIUM"

    def test_low_confidence(self):
        policy = ConfidencePolicy(high_threshold=0.7, medium_threshold=0.4, low_threshold=0.2)
        assert policy.classify_confidence(0.1) == "LOW"

    def test_apply_marks_needs_review(self, trained_classifier):
        preds = trained_classifier.predict(["router bgp 65000"])
        policy = ConfidencePolicy(high_threshold=0.99)
        applied = apply_confidence_policy(preds, policy)
        assert applied[0].needs_review is True

    def test_tune_thresholds(self, trained_classifier, examples):
        policy = tune_thresholds(examples, trained_classifier, target_precision=0.5)
        assert 0.0 < policy.high_threshold <= 1.0
        assert policy.medium_threshold <= policy.high_threshold


# ---------------------------------------------------------------------------
# Ambiguous detection
# ---------------------------------------------------------------------------

class TestAmbiguousDetection:
    def test_ambiguous_in_training_labels(self, trained_classifier):
        assert AMBIGUOUS_LABEL in list(trained_classifier.classes_)

    def test_ambiguous_example_prediction(self, trained_classifier, policy):
        metrics = evaluate(
            [NLPExample(
                raw_text="ip flow-export source Loopback0",
                vendor="Cisco", security_concept=AMBIGUOUS_LABEL,
                normalized_field=None, value=None, status="AMBIGUOUS",
                source_file="test", source_line=0,
            )],
            trained_classifier, policy, split_name="test",
        )
        assert metrics.total_examples == 1


# ---------------------------------------------------------------------------
# Hard negatives
# ---------------------------------------------------------------------------

class TestHardNegatives:
    def test_generate_creates_examples(self, examples):
        negatives = generate_hard_negatives(examples)
        assert len(negatives) > 0
        for neg in negatives:
            assert neg.status == "HARD_NEGATIVE"
            assert neg.security_concept == NON_SECURITY_LABEL

    def test_comment_with_security_keyword(self, trained_classifier, policy):
        pred = hybrid_predict(
            "! ssh access is configured on line vty 0 4",
            trained_classifier, policy,
        )
        # Comments should NOT be classified as security configs
        # If the model gets it wrong, it should at least trigger review
        assert pred.predicted_concept in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL) or pred.needs_review

    def test_description_with_security_keyword(self, trained_classifier, policy):
        pred = hybrid_predict(
            "description SSH uplink to core-router",
            trained_classifier, policy,
        )
        assert pred.predicted_concept in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL) or pred.needs_review

    def test_evaluate_hard_negatives(self, trained_classifier, policy, examples):
        negatives = generate_hard_negatives(examples)
        if negatives:
            results = evaluate_hard_negatives(negatives, trained_classifier, policy)
            assert "false_positive_rate" in results
            assert "total_hard_negatives" in results


# ---------------------------------------------------------------------------
# Malformed configurations
# ---------------------------------------------------------------------------

class TestMalformedConfig:
    def test_empty_string(self, trained_classifier):
        pred = trained_classifier.predict_one("")
        assert isinstance(pred, NLPPrediction)

    def test_whitespace_only(self, trained_classifier):
        pred = trained_classifier.predict_one("   \t  \n  ")
        assert isinstance(pred, NLPPrediction)

    def test_very_long_line(self, trained_classifier):
        pred = trained_classifier.predict_one("x " * 1000)
        assert isinstance(pred, NLPPrediction)

    def test_special_characters(self, trained_classifier):
        pred = trained_classifier.predict_one("!@#$%^&*() {}")
        assert isinstance(pred, NLPPrediction)


# ---------------------------------------------------------------------------
# File-level leakage check
# ---------------------------------------------------------------------------

class TestLeakageCheck:
    def test_no_leakage_when_disjoint(self):
        train = [NLPExample(raw_text="a", vendor="X", security_concept="A",
                           normalized_field=None, value=None, status="UNMAPPED",
                           source_file="file1.conf", source_line=1)]
        val = [NLPExample(raw_text="b", vendor="X", security_concept="A",
                         normalized_field=None, value=None, status="UNMAPPED",
                         source_file="file2.conf", source_line=1)]
        test = [NLPExample(raw_text="c", vendor="X", security_concept="A",
                          normalized_field=None, value=None, status="UNMAPPED",
                          source_file="file3.conf", source_line=1)]
        ok, msg = verify_no_leakage(train, val, test)
        assert ok is True

    def test_leakage_detected(self):
        train = [NLPExample(raw_text="a", vendor="X", security_concept="A",
                           normalized_field=None, value=None, status="UNMAPPED",
                           source_file="shared.conf", source_line=1)]
        val = [NLPExample(raw_text="b", vendor="X", security_concept="A",
                         normalized_field=None, value=None, status="UNMAPPED",
                         source_file="shared.conf", source_line=2)]
        test = [NLPExample(raw_text="c", vendor="X", security_concept="A",
                          normalized_field=None, value=None, status="UNMAPPED",
                          source_file="other.conf", source_line=1)]
        ok, msg = verify_no_leakage(train, val, test)
        assert ok is False
        assert "LEAKAGE" in msg

    @pytest.mark.skipif(not DATASET_DIR.exists(), reason="Dataset not available")
    def test_real_dataset_no_leakage(self):
        from auditor.training.nlp_pipeline import load_dataset
        train, val, test = load_dataset(DATASET_DIR)
        ok, msg = verify_no_leakage(train, val, test)
        assert ok is True, msg


# ---------------------------------------------------------------------------
# Cross-vendor evaluation
# ---------------------------------------------------------------------------

class TestCrossVendor:
    @pytest.mark.skipif(not DATASET_DIR.exists(), reason="Dataset not available")
    def test_vendor_held_out(self):
        from auditor.training.nlp_pipeline import load_dataset
        train, val, test = load_dataset(DATASET_DIR)
        all_data = train + val + test
        result = vendor_held_out_evaluate(all_data, "Cisco")
        if result is not None:
            assert result["held_out_vendor"] == "Cisco"
            assert result["test_size"] > 0
            assert 0 <= result["metrics"]["concept_accuracy"] <= 1.0

    def test_vendor_held_out_insufficient(self):
        examples = [
            NLPExample(raw_text="test", vendor="OnlyVendor",
                      security_concept=NON_SECURITY_LABEL, normalized_field=None,
                      value=None, status="UNMAPPED", source_file="f.conf",
                      source_line=1),
        ]
        result = vendor_held_out_evaluate(examples, "OnlyVendor")
        assert result is None


# ---------------------------------------------------------------------------
# Human approval / rejection / learned mappings
# ---------------------------------------------------------------------------

class TestHumanInTheLoop:
    @pytest.mark.skipif(not DATASET_DIR.exists(), reason="Dataset not available")
    def test_simulation(self):
        from auditor.training.nlp_pipeline import load_dataset
        train, val, test = load_dataset(DATASET_DIR)
        clf = SecurityConceptClassifier(random_seed=42)
        clf.fit([e.raw_text for e in train], [e.security_concept for e in train])
        policy = ConfidencePolicy()
        result = simulate_human_loop(test, clf, policy)
        assert "suggestions" in result
        assert result.get("nlp_produced_pass") is False
        assert result.get("nlp_produced_fail") is False

    def test_rejection_not_learned(self):
        from auditor.training.mappings import LearnedMapping, LearnedMappingStore
        with tempfile.TemporaryDirectory() as tmpdir:
            store = LearnedMappingStore(Path(tmpdir) / "mappings.jsonl")
            mapping = LearnedMapping(
                mapping_id="test_reject",
                vendor="cisco",
                pattern="test-pattern",
                field="ssh_enabled",
                extraction_strategy="exact",
                status="pending",
                approval_state="pending",
            )
            store.create_mapping(mapping)
            store.reject_mapping("test_reject")
            active = store.get_active_approved_mappings()
            assert all(m.mapping_id != "test_reject" for m in active)

    def test_approved_mapping_becomes_deterministic(self):
        from auditor.training.mappings import LearnedMapping, LearnedMappingStore
        with tempfile.TemporaryDirectory() as tmpdir:
            store = LearnedMappingStore(Path(tmpdir) / "mappings.jsonl")
            mapping = LearnedMapping(
                mapping_id="test_approve",
                vendor="cisco",
                pattern="custom-ssh-enable",
                field="ssh_enabled",
                extraction_strategy="exact",
                status="pending",
                approval_state="pending",
            )
            store.create_mapping(mapping)
            store.approve_mapping("test_approve")
            active = store.get_active_approved_mappings()
            assert any(m.mapping_id == "test_approve" for m in active)


# ---------------------------------------------------------------------------
# AI cannot produce PASS / FAIL
# ---------------------------------------------------------------------------

class TestAICannotProduceCompliance:
    def test_prediction_has_no_pass_fail(self, trained_classifier):
        texts = ["snmp-server community public RO", "exec-timeout 5 0", "router bgp 65000"]
        preds = trained_classifier.predict(texts)
        for pred in preds:
            assert pred.predicted_concept not in ("PASS", "FAIL")
            assert "PASS" not in str(pred.predicted_concept).upper() or pred.predicted_concept == "PASS" is False

    def test_nlp_prediction_structure(self, trained_classifier):
        pred = trained_classifier.predict_one("snmp-server community test RO")
        assert hasattr(pred, "predicted_concept")
        assert hasattr(pred, "predicted_field")
        assert hasattr(pred, "confidence")
        assert not hasattr(pred, "compliance_result")
        assert not hasattr(pred, "pass_fail")

    def test_deterministic_predict_no_compliance(self):
        pred = deterministic_predict("snmp-server community public RO")
        assert pred.predicted_concept not in ("PASS", "FAIL")

    def test_hybrid_predict_no_compliance(self, trained_classifier, policy):
        pred = hybrid_predict("snmp-server community public RO", trained_classifier, policy)
        assert pred.predicted_concept not in ("PASS", "FAIL")


# ---------------------------------------------------------------------------
# Parser isolation / existing vendor isolation
# ---------------------------------------------------------------------------

class TestIsolation:
    def test_nlp_does_not_import_compliance_engine(self):
        import auditor.training.nlp_pipeline as mod
        source = Path(mod.__file__).read_text(encoding="utf-8")
        assert "ComplianceEngine" not in source
        assert "from ..engine" not in source

    def test_nlp_does_not_modify_baseline(self, trained_classifier):
        pred = trained_classifier.predict_one("snmp-server community test RO")
        assert not hasattr(pred, "baseline")
        assert not hasattr(pred, "security_baseline_model")

    def test_prediction_is_suggestion_only(self, trained_classifier):
        pred = trained_classifier.predict_one("exec-timeout 5 0")
        assert pred.source == "nlp"
        assert hasattr(pred, "needs_review")
        assert hasattr(pred, "is_unknown")


# ---------------------------------------------------------------------------
# Evaluation metrics
# ---------------------------------------------------------------------------

class TestEvaluationMetrics:
    def test_evaluate_produces_metrics(self, trained_classifier, policy, examples):
        metrics = evaluate(examples, trained_classifier, policy, split_name="unit")
        assert isinstance(metrics, NLPMetrics)
        assert metrics.total_examples == len(examples)
        assert 0.0 <= metrics.concept_accuracy <= 1.0
        assert 0.0 <= metrics.concept_f1_macro <= 1.0
        assert 0.0 <= metrics.false_mapping_rate <= 1.0

    def test_deterministic_baseline_runs(self, examples):
        metrics = evaluate_deterministic(examples)
        assert isinstance(metrics, NLPMetrics)
        assert metrics.split_name == "deterministic"

    def test_hybrid_evaluation_runs(self, trained_classifier, policy, examples):
        metrics = evaluate_hybrid(examples, trained_classifier, policy)
        assert isinstance(metrics, NLPMetrics)
        assert metrics.split_name == "hybrid"

    def test_per_class_metrics(self, trained_classifier, policy, examples):
        metrics = evaluate(examples, trained_classifier, policy, split_name="unit")
        assert len(metrics.per_class) > 0
        for cls, stats in metrics.per_class.items():
            assert "precision" in stats
            assert "recall" in stats
            assert "f1" in stats

    def test_confusion_matrix(self, trained_classifier, policy, examples):
        metrics = evaluate(examples, trained_classifier, policy, split_name="unit")
        assert metrics.confusion is not None
        assert metrics.class_names is not None
        assert len(metrics.confusion) == len(metrics.class_names)

    def test_calibration_stats(self, trained_classifier, policy, examples):
        metrics = evaluate(examples, trained_classifier, policy, split_name="unit")
        assert metrics.confidence_calibration is not None
        assert "expected_calibration_error" in metrics.confidence_calibration


# ---------------------------------------------------------------------------
# Dataset loading (integration, skipped if dataset not available)
# ---------------------------------------------------------------------------

class TestDatasetLoading:
    @pytest.mark.skipif(not DATASET_DIR.exists(), reason="Dataset not available")
    def test_load_all_splits(self):
        from auditor.training.nlp_pipeline import load_dataset
        train, val, test = load_dataset(DATASET_DIR)
        assert len(train) > 0
        assert len(val) > 0
        assert len(test) > 0

    @pytest.mark.skipif(not DATASET_DIR.exists(), reason="Dataset not available")
    def test_dataset_stats(self):
        from auditor.training.nlp_pipeline import load_dataset
        train, _, _ = load_dataset(DATASET_DIR)
        stats = dataset_stats(train)
        assert stats.total == len(train)
        assert stats.mapped + stats.unmapped + stats.ambiguous == stats.total

    @pytest.mark.skipif(not DATASET_DIR.exists(), reason="Dataset not available")
    def test_split_sizes_match_metadata(self):
        from auditor.training.nlp_pipeline import load_dataset
        train, val, test = load_dataset(DATASET_DIR)
        assert len(train) == 202
        assert len(val) == 63
        assert len(test) == 54


# ---------------------------------------------------------------------------
# Full pipeline (integration, skipped if dataset not available)
# ---------------------------------------------------------------------------

class TestFullPipeline:
    @pytest.mark.skipif(not DATASET_DIR.exists(), reason="Dataset not available")
    def test_full_pipeline(self):
        from auditor.training.nlp_pipeline import run_full_pipeline
        with tempfile.TemporaryDirectory() as tmpdir:
            report = run_full_pipeline(DATASET_DIR, Path(tmpdir))
            assert report["dataset"]["data_leakage"] == "NO"
            assert report["security_guarantees"]["nlp_produced_pass"] is False
            assert report["security_guarantees"]["nlp_produced_fail"] is False
            assert report["security_guarantees"]["false_compliance_results"] == 0
            assert report["data_limitations"]["real_device_configurations"] == 0

            eval_path = Path(tmpdir) / "evaluation_results.json"
            assert eval_path.is_file()

            model_path = Path(tmpdir) / "nlp_model" / "concept_classifier.joblib"
            assert model_path.is_file()
