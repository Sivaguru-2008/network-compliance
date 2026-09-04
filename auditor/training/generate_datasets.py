"""Dataset Generation and Pipeline Ingestion Script.

Discovers, inventories, classifies, normalizes, extracts values, and partitions:
1. Kentik config-snippets (PUBLIC_CONFIGURATION_SNIPPET)
2. Cisco DevNet netconf-examples (PUBLIC_NETCONF_EXAMPLE)

Outputs structured, logically separated datasets under:
    dataset/
        official/
        public_config/
        public_netconf/
        synthetic/
        real_device/
        unknown/
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from .public_dataset import (
    OFFICIAL_DOC_REFERENCES,
    DeterministicBaselineMatcher,
    DevNetNetconfScanner,
    HybridSemanticMatcher,
    NLPSemanticLayer,
    ProvenanceClassification,
    PublicDatasetScanner,
    SecuritySnippet,
    partition_snippets_without_leakage,
    run_nlp_benchmark,
)


def generate_all_datasets(
    repo_root: Path = Path("."),
    dataset_base: Path = Path("dataset"),
) -> Dict[str, Any]:
    """Execute complete dataset discovery, classification, partitioning, and benchmark suite."""
    kentik_dir = repo_root / "config-snippets-master"
    devnet_dir = repo_root / "netconf-examples-master"

    # Setup directories
    official_dir = dataset_base / "official"
    public_config_dir = dataset_base / "public_config"
    public_config_legacy_dir = dataset_base / "public_config_snippets"
    public_netconf_dir = dataset_base / "public_netconf"
    synthetic_dir = dataset_base / "synthetic"
    real_device_dir = dataset_base / "real_device"
    unknown_dir = dataset_base / "unknown"

    for d in [
        official_dir,
        public_config_dir,
        public_config_dir / "train",
        public_config_dir / "validation",
        public_config_dir / "test",
        public_config_legacy_dir,
        public_config_legacy_dir / "train",
        public_config_legacy_dir / "validation",
        public_config_legacy_dir / "test",
        public_netconf_dir,
        synthetic_dir,
        real_device_dir,
        unknown_dir,
    ]:
        d.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # 1. Kentik config-snippets Scanner
    # -------------------------------------------------------------------------
    scanner = PublicDatasetScanner(kentik_dir)
    kentik_inventory = scanner.scan_inventory()
    extracted_snippets = scanner.extract_security_snippets()

    # Partition snippets without data leakage (file-level disjoint)
    train_snippets, val_snippets, test_snippets = partition_snippets_without_leakage(
        extracted_snippets, train_ratio=0.70, val_ratio=0.15, seed=42
    )

    # Cross-vendor equivalence mapping definition
    cross_vendor_mapping = {
        "snmp_community_access": {
            "baseline_field": "snmp_communities",
            "concept": "SNMP v1/v2c community string and access control",
            "vendors": {
                "Cisco": {"syntax": "snmp-server community <name> [RO|RW]", "doc": OFFICIAL_DOC_REFERENCES["Cisco"]["snmp"]},
                "Juniper": {"syntax": "set snmp community <name> authorization [read-only|read-write]", "doc": OFFICIAL_DOC_REFERENCES["Juniper"]["snmp"]},
                "Arista": {"syntax": "snmp-server community <name> [ro|rw]", "doc": OFFICIAL_DOC_REFERENCES["Arista"]["snmp"]},
                "Huawei": {"syntax": "snmp-agent community read <name>", "doc": OFFICIAL_DOC_REFERENCES["Huawei"]["snmp"]},
                "Mikrotik": {"syntax": "/snmp community add name=<name> read-access=yes", "doc": OFFICIAL_DOC_REFERENCES["Mikrotik"]["snmp"]},
                "Extreme": {"syntax": "snmp-server community <name> ro", "doc": OFFICIAL_DOC_REFERENCES["Extreme"]["snmp"]},
                "Ubiquiti": {"syntax": "set service snmp community <name> authorization ro", "doc": OFFICIAL_DOC_REFERENCES["Ubiquiti"]["snmp"]},
                "Nokia": {"syntax": "configure snmp community <name> access read-only", "doc": OFFICIAL_DOC_REFERENCES["Nokia"]["snmp"]},
            },
        },
        "snmp_agent_state": {
            "baseline_field": "snmp_agent_enabled",
            "concept": "Administrative SNMP agent activation",
            "vendors": {
                "Cisco": {"syntax": "snmp-server enable traps", "doc": OFFICIAL_DOC_REFERENCES["Cisco"]["snmp"]},
                "Juniper": {"syntax": "set snmp ...", "doc": OFFICIAL_DOC_REFERENCES["Juniper"]["snmp"]},
                "Arista": {"syntax": "snmp-server enable traps", "doc": OFFICIAL_DOC_REFERENCES["Arista"]["snmp"]},
                "Mikrotik": {"syntax": "/snmp set enabled=yes", "doc": OFFICIAL_DOC_REFERENCES["Mikrotik"]["snmp"]},
            },
        },
        "ssh_protocol_version": {
            "baseline_field": "ssh_version",
            "concept": "Enforced SSH protocol version",
            "vendors": {
                "Cisco": {"syntax": "ip ssh version 2", "doc": OFFICIAL_DOC_REFERENCES["Cisco"]["ssh"]},
                "Juniper": {"syntax": "set system services ssh protocol-version v2", "doc": OFFICIAL_DOC_REFERENCES["Juniper"]["ssh"]},
                "Arista": {"syntax": "management ssh / ip ssh version 2", "doc": OFFICIAL_DOC_REFERENCES["Arista"]["ssh"]},
                "Huawei": {"syntax": "ssh server compatible-ssh1x disable", "doc": OFFICIAL_DOC_REFERENCES["Huawei"]["ssh"]},
            },
        },
        "ssh_access_control": {
            "baseline_field": "ssh_enabled",
            "concept": "SSH administrative remote access service",
            "vendors": {
                "Cisco": {"syntax": "transport input ssh / ip ssh", "doc": OFFICIAL_DOC_REFERENCES["Cisco"]["ssh"]},
                "Juniper": {"syntax": "set system services ssh", "doc": OFFICIAL_DOC_REFERENCES["Juniper"]["ssh"]},
                "Arista": {"syntax": "management ssh", "doc": OFFICIAL_DOC_REFERENCES["Arista"]["ssh"]},
                "Mikrotik": {"syntax": "/ip service set ssh disabled=no", "doc": OFFICIAL_DOC_REFERENCES["Mikrotik"]["ssh"]},
                "Vyatta": {"syntax": "set service ssh", "doc": OFFICIAL_DOC_REFERENCES["Vyatta"]["ssh"]},
            },
        },
        "syslog_destination_hosts": {
            "baseline_field": "logging_hosts",
            "concept": "Remote syslog collector destination",
            "vendors": {
                "Cisco": {"syntax": "logging host <ip>", "doc": OFFICIAL_DOC_REFERENCES["Cisco"]["logging"]},
                "Juniper": {"syntax": "set system syslog host <ip>", "doc": OFFICIAL_DOC_REFERENCES["Juniper"]["logging"]},
                "Arista": {"syntax": "logging host <ip>", "doc": OFFICIAL_DOC_REFERENCES["Arista"]["logging"]},
                "Huawei": {"syntax": "info-center loghost <ip>", "doc": OFFICIAL_DOC_REFERENCES["Huawei"]["logging"]},
                "Mikrotik": {"syntax": "/system logging action set remote target=remote remote=<ip>", "doc": OFFICIAL_DOC_REFERENCES["Mikrotik"]["logging"]},
            },
        },
        "ntp_time_synchronization": {
            "baseline_field": "ntp_servers",
            "concept": "Network Time Protocol authoritative clock source",
            "vendors": {
                "Cisco": {"syntax": "ntp server <ip>", "doc": OFFICIAL_DOC_REFERENCES["Cisco"]["ntp"]},
                "Juniper": {"syntax": "set system ntp server <ip>", "doc": OFFICIAL_DOC_REFERENCES["Juniper"]["ntp"]},
                "Arista": {"syntax": "ntp server <ip>", "doc": OFFICIAL_DOC_REFERENCES["Arista"]["ntp"]},
                "Huawei": {"syntax": "ntp-service unicast-server <ip>", "doc": OFFICIAL_DOC_REFERENCES["Huawei"]["ntp"]},
                "Mikrotik": {"syntax": "/system ntp client set servers=<ip>", "doc": OFFICIAL_DOC_REFERENCES["Mikrotik"]["ntp"]},
            },
        },
        "session_inactivity_timeout": {
            "baseline_field": "vty_exec_timeout_seconds",
            "concept": "Administrative session idle inactivity timeout",
            "vendors": {
                "Cisco": {"syntax": "exec-timeout <min> <sec>", "doc": OFFICIAL_DOC_REFERENCES["Cisco"]["vty"]},
                "Arista": {"syntax": "exec-timeout <min>", "doc": OFFICIAL_DOC_REFERENCES["Arista"]["ssh"]},
                "Fortinet": {"syntax": "set admintimeout <min>", "doc": "FortiOS Administration Guide: Admin Timeout"},
            },
        },
    }

    # Write Official documentation dataset
    with open(official_dir / "documentation_references.json", "w", encoding="utf-8") as f:
        json.dump(OFFICIAL_DOC_REFERENCES, f, indent=2)

    with open(official_dir / "verified_ground_truth.json", "w", encoding="utf-8") as f:
        json.dump(cross_vendor_mapping, f, indent=2)

    # Write Kentik Public Config dataset to both directories for seamless compatibility
    for target_dir in [public_config_dir, public_config_legacy_dir]:
        with open(target_dir / "inventory.json", "w", encoding="utf-8") as f:
            json.dump([item.to_dict() for item in kentik_inventory], f, indent=2)

        with open(target_dir / "extracted_security_snippets.json", "w", encoding="utf-8") as f:
            json.dump([s.to_dict() for s in extracted_snippets], f, indent=2)

        with open(target_dir / "cross_vendor_mapping.json", "w", encoding="utf-8") as f:
            json.dump(cross_vendor_mapping, f, indent=2)

        with open(target_dir / "train" / "snippets.json", "w", encoding="utf-8") as f:
            json.dump([s.to_nlp_example_dict() for s in train_snippets], f, indent=2)

        with open(target_dir / "validation" / "snippets.json", "w", encoding="utf-8") as f:
            json.dump([s.to_nlp_example_dict() for s in val_snippets], f, indent=2)

        with open(target_dir / "test" / "snippets.json", "w", encoding="utf-8") as f:
            json.dump([s.to_nlp_example_dict() for s in test_snippets], f, indent=2)

    # Write separate Unknown / Ambiguous datasets
    unmapped_snippets = [s.to_nlp_example_dict() for s in extracted_snippets if s.status == "UNMAPPED"]
    ambiguous_snippets = [s.to_nlp_example_dict() for s in extracted_snippets if s.status == "AMBIGUOUS"]
    mapped_snippets = [s.to_nlp_example_dict() for s in extracted_snippets if s.status == "MAPPED"]

    with open(unknown_dir / "unmapped_snippets.json", "w", encoding="utf-8") as f:
        json.dump(unmapped_snippets, f, indent=2)

    with open(unknown_dir / "ambiguous_snippets.json", "w", encoding="utf-8") as f:
        json.dump(ambiguous_snippets, f, indent=2)

    # Write Kentik Metadata
    kentik_vendors = sorted({item.vendor for item in kentik_inventory})
    kentik_meta = {
        "source_name": "Kentik config-snippets",
        "dataset_classification": ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
        "provenance": ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
        "real_device": False,
        "total_inventory_files": len(kentik_inventory),
        "total_extracted_snippets": len(extracted_snippets),
        "mapped_count": len(mapped_snippets),
        "unmapped_count": len(unmapped_snippets),
        "ambiguous_count": len(ambiguous_snippets),
        "vendors_count": len(kentik_vendors),
        "vendors": kentik_vendors,
        "splits": {
            "train": {"count": len(train_snippets), "files": len(set(s.source_file for s in train_snippets))},
            "validation": {"count": len(val_snippets), "files": len(set(s.source_file for s in val_snippets))},
            "test": {"count": len(test_snippets), "files": len(set(s.source_file for s in test_snippets))},
        },
    }
    for target_dir in [public_config_dir, public_config_legacy_dir]:
        with open(target_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(kentik_meta, f, indent=2)

    # -------------------------------------------------------------------------
    # 2. Cisco DevNet NETCONF Scanner
    # -------------------------------------------------------------------------
    devnet_scanner = DevNetNetconfScanner(devnet_dir)
    devnet_items = devnet_scanner.scan_classified_items()

    with open(public_netconf_dir / "inventory.json", "w", encoding="utf-8") as f:
        json.dump([item.to_dict() for item in devnet_items], f, indent=2)

    with open(public_netconf_dir / "classified_items.json", "w", encoding="utf-8") as f:
        json.dump([item.to_dict() for item in devnet_items], f, indent=2)

    devnet_configs = [item.to_dict() for item in devnet_items if item.contains_actual_config]
    with open(public_netconf_dir / "extracted_configs.json", "w", encoding="utf-8") as f:
        json.dump(devnet_configs, f, indent=2)

    devnet_meta = {
        "source_name": "Cisco DevNet netconf-examples",
        "dataset_classification": ProvenanceClassification.PUBLIC_NETCONF_EXAMPLE.value,
        "provenance": ProvenanceClassification.PUBLIC_NETCONF_EXAMPLE.value,
        "real_device": False,
        "total_files": len(devnet_items),
        "modules": ["netconf-101", "netconf-102", "netconf-103"],
        "classifications": {
            "CONFIGURATION": len([i for i in devnet_items if i.classification == "CONFIGURATION"]),
            "NETCONF_API_EXAMPLE": len([i for i in devnet_items if i.classification == "NETCONF/API EXAMPLE"]),
            "AUTOMATION_CODE": len([i for i in devnet_items if i.classification == "AUTOMATION CODE"]),
            "DOCUMENTATION": len([i for i in devnet_items if i.classification == "DOCUMENTATION"]),
            "OTHER": len([i for i in devnet_items if i.classification == "OTHER"]),
        },
        "actual_configuration_files": len(devnet_configs),
    }
    with open(public_netconf_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(devnet_meta, f, indent=2)

    # -------------------------------------------------------------------------
    # 3. Real Device Dataset Directory (Explicit absence verification)
    # -------------------------------------------------------------------------
    real_device_readme = (
        "# Real Device Dataset\n\n"
        "Status: No production enterprise device configurations are present.\n"
        "Provenance: REAL_DEVICE_CONFIGURATION\n"
        "Total Count: 0\n"
        "Real Device Flag: false\n\n"
        "All samples and public snippets in this repository originate from public repositories "
        "or synthetic fixtures. Real-device provenance has not been established for any external snippet.\n"
    )
    with open(real_device_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(real_device_readme)

    # -------------------------------------------------------------------------
    # 4. Run NLP Benchmarks across Test Partition
    # -------------------------------------------------------------------------
    det_matcher = DeterministicBaselineMatcher()
    nlp_matcher = NLPSemanticLayer()
    hybrid_matcher = HybridSemanticMatcher()

    det_res = run_nlp_benchmark(test_snippets, det_matcher, "Deterministic Matcher")
    nlp_res = run_nlp_benchmark(test_snippets, nlp_matcher, "NLP Semantic Layer")
    hyb_res = run_nlp_benchmark(test_snippets, hybrid_matcher, "Hybrid Semantic Matcher")

    benchmark_summary = {
        "test_split_size": len(test_snippets),
        "deterministic": det_res.to_dict(),
        "nlp": nlp_res.to_dict(),
        "hybrid": hyb_res.to_dict(),
    }

    for target_dir in [public_config_dir, public_config_legacy_dir]:
        with open(target_dir / "benchmark_results.json", "w", encoding="utf-8") as f:
            json.dump(benchmark_summary, f, indent=2)

    return {
        "kentik_meta": kentik_meta,
        "devnet_meta": devnet_meta,
        "benchmark_summary": benchmark_summary,
    }


if __name__ == "__main__":
    res = generate_all_datasets()
    print("Dataset generation completed successfully:")
    print(json.dumps(res, indent=2))
