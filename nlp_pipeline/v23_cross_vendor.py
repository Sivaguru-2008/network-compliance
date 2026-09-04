"""V2.3 Cross-Vendor Security Semantics & Generalization Engine.

Implements Phases 8-13:
- Rich Canonical Semantic Representation (26+ features + relationship graph)
- Feature modes: RAW ONLY, CANONICAL ONLY, RAW + CANONICAL, RAW + CANONICAL + CHAR
- True Zero-Shot Cross-Vendor Evaluation on Held-Out Vendors
- Leave-One-Vendor-Out (LOVO) Evaluation Matrix
"""

import collections
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score, recall_score
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import LabelEncoder


def extract_rich_canonical_semantics(text: str) -> Dict[str, Any]:
    """Extract vendor-agnostic canonical security features & relationship graph from text."""
    t_lower = text.lower()
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.strip().startswith("!")]

    # Core Security Features
    has_telnet = bool(re.search(r"(?:transport\s+input\s+.*telnet|transport\s+input\s+all|set\s+system\s+services\s+telnet|allowaccess.*telnet|telnet\s+server\s+enable|/ip\s+service.*telnet|protocol\s+telnet)", t_lower))
    has_ssh = bool(re.search(r"(?:transport\s+input\s+.*ssh|set\s+system\s+services\s+ssh|allowaccess.*ssh|stelnet\s+server\s+enable|/ip\s+service.*ssh|protocol\s+https|ip\s+ssh)", t_lower))

    has_http = bool(re.search(r"(?:(?<!no\s)ip\s+http\s+server\b|allowaccess.*http\b|set\s+system\s+services\s+web-management\s+http|http\s+server\s+enable|/ip\s+service.*www\b)", t_lower))
    has_https = bool(re.search(r"(?:ip\s+http\s+secure-server|protocol\s+https|allowaccess.*https|web-management\s+https|http\s+secure-server|/ip\s+service.*www-ssl)", t_lower))

    has_snmp_default = bool(re.search(r"(?:snmp.*(?:public|private)|community\s+(?:public|private))", t_lower))
    has_snmp_v3 = bool(re.search(r"(?:snmp.*v3|group\s+\S+\s+v3|user\s+\S+\s+\S+\s+v3)", t_lower))

    has_logging_disabled = bool(re.search(r"(?:no\s+logging\s+host|no\s+logging\s+buffered|undo\s+info-center)", t_lower))
    has_logging_remote = bool(re.search(r"(?:logging\s+host\s+\d+|info-center\s+loghost\s+\d+|configure\s+log\s+syslog|set\s+system\s+syslog\s+host)", t_lower))

    has_ntp_disabled = bool(re.search(r"(?:no\s+ntp|undo\s+ntp|enabled=no)", t_lower))
    has_ntp_remote = bool(re.search(r"(?:ntp\s+server\s+\d+|set\s+system\s+ntp\s+server|ntp-service\s+unicast-server|primary-ntp=)", t_lower))

    has_weak_crypto = bool(re.search(r"(?:3des|esp-3des|des\b|esp-des|md5|esp-md5-hmac|ike-legacy|group1\b|group2\b|group5\b)", t_lower))
    has_strong_crypto = bool(re.search(r"(?:aes-256-gcm|esp-gcm|aes-256|esp-aes\s+256|sha256|sha-256|group14|group19|group20|suite-b)", t_lower))

    has_unrestricted_fw = bool(re.search(r"(?:permit\s+ip\s+any\s+any\b(?!\s*established)|allow-any\s+match\s+source-address\s+any|allow-all\s+from\s+any\s+to\s+any|permit\s+any\s+any\b)", t_lower))
    has_restricted_fw = bool(re.search(r"(?:permit\s+tcp|permit\s+udp|deny\s+ip\s+any\s+any|destination-address|service-https)", t_lower))

    has_plaintext_pw = bool(re.search(r"(?:enable\s+password\b|password\s+0\s+|password\s+7\s+)", t_lower))
    has_secret_pw = bool(re.search(r"(?:enable\s+secret\b|encrypted-password|secret\s+5\s+|secret\s+8\s+|secret\s+9\s+)", t_lower))

    has_aaa = bool(re.search(r"(?:aaa\s+new-model|aaa\s+authentication|set\s+system\s+login|auth-mode)", t_lower))
    has_tacacs = bool(re.search(r"(?:tacacs\+?|tacacs-server)", t_lower))
    has_radius = bool(re.search(r"(?:radius|radius-server)", t_lower))

    # Relationships and Structure
    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    interface_matches = re.findall(r'(?:interface\s+\S+|edit\s+["\']?port\d+|set\s+interfaces\s+\S+|net\s+self\s+\S+)', text, re.IGNORECASE)
    acl_matches = re.findall(r'(?:access-list|ip\s+access-list|security\s+policies|firewall\s+policy|acl\s+number|rulebase\s+security)', text, re.IGNORECASE)

    feats = {
        # Core Findings & Postures
        "telnet_enabled": 1.0 if has_telnet else 0.0,
        "ssh_enabled": 1.0 if has_ssh else 0.0,
        "http_enabled": 1.0 if has_http else 0.0,
        "https_enabled": 1.0 if has_https else 0.0,
        "snmp_default_community": 1.0 if has_snmp_default else 0.0,
        "snmp_v3_enabled": 1.0 if has_snmp_v3 else 0.0,
        "logging_disabled": 1.0 if has_logging_disabled else 0.0,
        "logging_remote_enabled": 1.0 if has_logging_remote else 0.0,
        "ntp_disabled": 1.0 if has_ntp_disabled else 0.0,
        "ntp_remote_enabled": 1.0 if has_ntp_remote else 0.0,
        "weak_crypto_present": 1.0 if has_weak_crypto else 0.0,
        "strong_crypto_present": 1.0 if has_strong_crypto else 0.0,
        "unrestricted_firewall_rule": 1.0 if has_unrestricted_fw else 0.0,
        "restricted_firewall_rule": 1.0 if has_restricted_fw else 0.0,
        "plaintext_password_present": 1.0 if has_plaintext_pw else 0.0,
        "enable_secret_present": 1.0 if has_secret_pw else 0.0,
        "aaa_configured": 1.0 if has_aaa else 0.0,
        "tacacs_configured": 1.0 if has_tacacs else 0.0,
        "radius_configured": 1.0 if has_radius else 0.0,
        # Structural Counts
        "num_ips": float(len(ip_matches)),
        "num_interfaces": float(len(interface_matches)),
        "num_acls": float(len(acl_matches)),
        # Relational indicators
        "rel_interface_has_ip": 1.0 if (len(interface_matches) > 0 and len(ip_matches) > 0) else 0.0,
        "rel_crypto_suite_b": 1.0 if (has_strong_crypto and not has_weak_crypto) else 0.0,
        "rel_secure_management": 1.0 if (has_ssh and not has_telnet and has_https and not has_http) else 0.0,
        "rel_insecure_management": 1.0 if (has_telnet or has_http or has_snmp_default or has_plaintext_pw) else 0.0,
    }
    return feats


class CrossVendorGeneralizationModel:
    """Multi-vendor generalized security finding classifier evaluating held-out platforms."""

    def __init__(self, feature_mode: str = "raw_canonical_char", random_seed: int = 42):
        self.feature_mode = feature_mode
        self.random_seed = random_seed
        self.label_encoder = LabelEncoder()
        self.dict_vec = DictVectorizer(sparse=True)
        self.word_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=4000, sublinear_tf=True)
        self.char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=6000, sublinear_tf=True)
        self.classifier = LogisticRegression(C=2.0, max_iter=1000, random_state=random_seed, class_weight="balanced", solver="lbfgs")
        self.fitted = False

    def _extract_features(self, texts: List[str], is_fit: bool = False):
        if self.feature_mode == "canonical_only":
            canon_dicts = [extract_rich_canonical_semantics(t) for t in texts]
            if is_fit:
                return self.dict_vec.fit_transform(canon_dicts)
            return self.dict_vec.transform(canon_dicts)

        elif self.feature_mode == "raw_only":
            if is_fit:
                return self.word_vec.fit_transform(texts)
            return self.word_vec.transform(texts)

        elif self.feature_mode == "raw_canonical":
            from scipy.sparse import hstack
            canon_dicts = [extract_rich_canonical_semantics(t) for t in texts]
            if is_fit:
                X_w = self.word_vec.fit_transform(texts)
                X_c = self.dict_vec.fit_transform(canon_dicts)
            else:
                X_w = self.word_vec.transform(texts)
                X_c = self.dict_vec.transform(canon_dicts)
            return hstack([X_w, X_c])

        else:  # raw_canonical_char
            from scipy.sparse import hstack
            canon_dicts = [extract_rich_canonical_semantics(t) for t in texts]
            if is_fit:
                X_w = self.word_vec.fit_transform(texts)
                X_ch = self.char_vec.fit_transform(texts)
                X_c = self.dict_vec.fit_transform(canon_dicts)
            else:
                X_w = self.word_vec.transform(texts)
                X_ch = self.char_vec.transform(texts)
                X_c = self.dict_vec.transform(canon_dicts)
            return hstack([X_w, X_ch, X_c])

    def fit(self, texts: List[str], labels: List[str]) -> "CrossVendorGeneralizationModel":
        y = self.label_encoder.fit_transform(labels)
        X = self._extract_features(texts, is_fit=True)
        self.classifier.fit(X, y)
        self.fitted = True
        return self

    def predict(self, texts: List[str]) -> List[str]:
        X = self._extract_features(texts, is_fit=False)
        pred_y = self.classifier.predict(X)
        return [str(self.label_encoder.classes_[i]) for i in pred_y]

    def evaluate(self, texts: List[str], labels: List[str], split_name: str = "held_out") -> Dict[str, Any]:
        preds = self.predict(texts)
        acc = accuracy_score(labels, preds)
        labels_present = sorted(set(labels + preds))
        f1_m = f1_score(labels, preds, labels=labels_present, average="macro", zero_division=0)
        f1_w = f1_score(labels, preds, labels=labels_present, average="weighted", zero_division=0)
        rec_m = recall_score(labels, preds, labels=labels_present, average="macro", zero_division=0)

        report = classification_report(labels, preds, output_dict=True, zero_division=0)
        critical_classes = [c for c in labels_present if any(k in c for k in ["DEFAULT", "UNRESTRICTED", "TELNET", "WEAK", "NON_COMPLIANT", "HTTP_MANAGEMENT", "ANY_TO_ANY", "ENABLE_PASSWORD"])]
        crit_recs = [report[c]["recall"] for c in critical_classes if c in report and report[c]["support"] > 0]
        avg_crit_rec = float(np.mean(crit_recs)) if crit_recs else rec_m

        return {
            "split": split_name,
            "total_samples": len(texts),
            "accuracy": round(float(acc), 4),
            "macro_f1": round(float(f1_m), 4),
            "weighted_f1": round(float(f1_w), 4),
            "critical_recall": round(float(avg_crit_rec), 4),
            "per_class": {k: v for k, v in report.items() if isinstance(v, dict)},
        }
