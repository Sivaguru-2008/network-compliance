from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SEVERITY_WEIGHTS = {
    'CRITICAL': 10,
    'HIGH': 7,
    'MEDIUM': 4,
    'LOW': 2,
    'INFO': 0,
}

SECURITY_CATEGORIES = [
    'authentication', 'authorization', 'access_control',
    'management_exposure', 'cryptography', 'logging',
    'monitoring', 'network_segmentation', 'routing',
    'firewall', 'acl', 'services', 'remote_access',
    'credential_security',
]

FINDING_CANONICAL_MAP = {
    'DEFAULT_CREDENTIAL': {'severity': 'CRITICAL', 'category': 'credential_security', 'cis': 'CIS-1.3.1'},
    'TELNET_ENABLED': {'severity': 'HIGH', 'category': 'remote_access', 'cis': 'CIS-2.1.1'},
    'HTTP_MANAGEMENT_ENABLED': {'severity': 'HIGH', 'category': 'management_exposure', 'cis': 'CIS-2.2.1'},
    'WEAK_CRYPTO': {'severity': 'HIGH', 'category': 'cryptography', 'cis': 'CIS-4.1.2'},
    'ANY_TO_ANY_RULE': {'severity': 'HIGH', 'category': 'firewall', 'cis': 'CIS-3.1.4'},
    'ENABLE_PASSWORD_PLAINTEXT': {'severity': 'HIGH', 'category': 'credential_security', 'cis': 'CIS-1.1.2'},
    'UNRESTRICTED_MANAGEMENT': {'severity': 'HIGH', 'category': 'access_control', 'cis': 'CIS-2.3.1'},
    'LOGGING_DISABLED': {'severity': 'MEDIUM', 'category': 'logging', 'cis': 'CIS-1.4.1'},
    'NTP_DISABLED': {'severity': 'MEDIUM', 'category': 'monitoring', 'cis': 'CIS-1.4.2'},
}


@dataclass
class SecurityFinding:
    finding_id: str
    finding_name: str
    severity: str
    category: str
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ''
    remediation: str = ''
    cis_control: str = ''


def merge_findings(findings: List[SecurityFinding]) -> List[SecurityFinding]:
    merged: Dict[str, SecurityFinding] = {}
    for f in findings:
        key = f.finding_name
        if key not in merged:
            merged[key] = f
        else:
            existing = merged[key]
            for ev in f.evidence:
                if ev not in existing.evidence:
                    existing.evidence.append(ev)
            existing.confidence = max(existing.confidence, f.confidence)
    return list(merged.values())


def calculate_risk_score(findings: List[SecurityFinding]) -> Dict[str, Any]:
    dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    total_risk = 0

    for f in findings:
        sev = f.severity.upper()
        if sev in dist:
            dist[sev] += 1
            total_risk += SEVERITY_WEIGHTS.get(sev, 0)

    finding_count = len(findings)
    posture = max(0.0, 100.0 - (total_risk * 2))

    return {
        'risk_score': total_risk,
        'security_posture_score': round(posture, 1),
        'finding_count': finding_count,
        'severity_distribution': dist,
    }
