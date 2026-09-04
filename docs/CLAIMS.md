# Technical Claims & Innovation Boundaries

This document provides a transparent, auditable breakdown of industry-standard baseline capabilities, our concrete engineering implementation, and potential research/architectural contributions.

---

## 1. Capability Differentiation

| Capability Area | Existing Industry State | Our Implementation | Technical Significance |
| :--- | :--- | :--- | :--- |
| **Multi-Vendor Configuration Ingestion** | Vendor-specific silos, proprietary compliance tools, or monolithic script libraries with hardcoded vendor logic. | 11+ independent parser modules registering to a decoupled parser registry; single-pass AST/block tokenization. | Decoupled seam architecture: adding a vendor requires zero changes to the core engine or existing vendor parsers. |
| **Semantic Representation** | Proprietary internal data structures or direct rule-to-vendor-command string regex matching. | Vendor-neutral `SecurityBaselineModel` with strongly-typed `Observation[T]` tracking origin, confidence, and line provenance. | Formal decoupling of vendor syntax from security requirements, allowing rules to be defined once across all vendors. |
| **Compliance Evaluation** | Binary PASS/FAIL evaluations that often swallow ambiguity, produce false passes, or lack traceability. | Ternary logic engine (`PASS`, `FAIL`, `NEEDS_REVIEW`) enforcing strict absence and ambiguity handling. | Eliminates false-pass vulnerabilities; unrecognized or absent configurations default safely to `NEEDS_REVIEW`. |
| **Handling Unrecognized / Unknown Syntax** | Unrecognized syntax is either ignored, fails catastrophically, or requires manual codebase patching. | Dynamic training queue with AI/NLP candidate suggestion, interactive human review, and persistent scoped storage. | Enables dynamic system adaptation to novel vendor syntax without code changes or restarts. |
| **AI Integration & Safety Boundary** | LLMs asked to directly determine compliance, leading to hallucinations, prompt injections, and non-reproducible verdicts. | Strict separation: AI *only* suggests candidate field/value interpretations with confidence. Compliance engine is 100% deterministic. | Eliminates LLM non-determinism and prompt-injection risks in security audit compliance verdicts. |
| **Data Provenance & Audit Trail** | High-level summary reports with missing or estimated line references; unclear data origin. | Cryptographic and line-exact provenance tracking (`source_file`, `source_line`, `line_number`, `origin`, `sha256`). | Publication-grade audit trail with verified CLI remediation blocks and complete provenance classification. |
| **Deployment & Privacy Constraints** | Cloud-dependent compliance scanners requiring plaintext configuration uploads to remote servers. | 100% offline-first architecture with local secrets redaction (passwords, SNMP strings, private keys, IP addresses). | Zero cloud egress or API credential dependencies required for enterprise compliance auditing. |

---

## 2. Potential Research Contributions

1. **Vendor-Neutral Semantic Normalization for Network Device Posture**:
   A formalized schema capturing security-critical network configurations into a vendor-agnostic object model, preventing combinatorial explosion when adding new vendors or frameworks.

2. **Provenance-Preserving Ternary Compliance Engine**:
   An evaluation engine that pairs formal ternary logic with origin tracking (`DETERMINISTIC`, `LEARNED`, `LLM`, `HYBRID`, `DEFAULT`, `ABSENT`), guaranteeing full audit traceability from compliance verdict to raw configuration line.

3. **Safe Human-in-the-Loop Adaptive Learning Architecture**:
   A closed-loop training pattern where machine learning or heuristic NLP proposes candidate semantic mappings that must be approved by human administrators before entering an isolated, vendor-scoped persistent mapping repository.

4. **Deterministic Gatekeeping after Non-Deterministic AI Interpretation**:
   A safety architecture proving that AI assistance can accelerate syntax interpretation without granting AI autonomous decision-making power over security compliance verdicts.

5. **Prompt-Injection Resilient Configuration Ingestion**:
   A structural isolation boundary ensuring configuration files containing adversarial instructions (`! Ignore previous instructions...`) are strictly processed as passive configuration data.

---

## 3. Explicit Non-Claims

- We do **not** claim to replace human network security engineers or administrators.
- We do **not** claim that heuristic or LLM suggestions are 100% accurate without human-in-the-loop review.
- We do **not** claim to possess proprietary real-device production configurations when synthetic and official vendor fixtures are used; all test dataset provenance is honestly documented.
- We do **not** claim "sub-millisecond" latency without publishing exact measured benchmark numbers and methodology across batch sizes.
