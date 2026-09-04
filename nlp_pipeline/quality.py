import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class QualityAssessment:
    source_file_id: str
    vendor: str
    platform: str
    configuration_hash: str
    normalized_hash: str
    dataset_version: str
    processing_status: str
    quality_score: float
    quality_tier: str
    reasons: List[str] = field(default_factory=list)
    breakdown: Dict[str, float] = field(default_factory=dict)


class DataQualityScorer:
    def score_configuration(
        self,
        config_text: str,
        file_id: str = '',
        vendor: str = 'unknown',
        platform: str = 'unknown',
        vendor_confidence: float = 1.0,
        dataset_version: str = '2.2.0'
    ) -> QualityAssessment:
        reasons = []
        breakdown = {}

        if not config_text or len(config_text.strip()) == 0:
            return QualityAssessment(
                source_file_id=file_id,
                vendor=vendor,
                platform=platform,
                configuration_hash='',
                normalized_hash='',
                dataset_version=dataset_version,
                processing_status='REJECTED',
                quality_score=0.0,
                quality_tier='REJECTED',
                reasons=['Empty configuration text'],
                breakdown={'corruption': 0.0, 'parseability': 0.0}
            )

        if chr(0) in config_text or '<html>' in config_text.lower() or '<!doctype html' in config_text.lower():
            return QualityAssessment(
                source_file_id=file_id,
                vendor=vendor,
                platform=platform,
                configuration_hash=hashlib.sha256(config_text.encode('utf-8', 'replace')).hexdigest()[:16],
                normalized_hash='',
                dataset_version=dataset_version,
                processing_status='REJECTED',
                quality_score=0.0,
                quality_tier='REJECTED',
                reasons=['Binary corruption or HTML response detected'],
                breakdown={'corruption': 0.0}
            )

        breakdown['no_corruption'] = 1.0

        lines = config_text.splitlines()
        content_lines = [l for l in lines if l.strip() and not l.strip().startswith(('!', '#', '//'))]
        if len(content_lines) < 3:
            parse_score = 0.2
            reasons.append('Very few valid syntax lines (< 3)')
        elif len(content_lines) < 10:
            parse_score = 0.6
        else:
            parse_score = 1.0
        breakdown['parseability'] = parse_score

        completeness_pts = 0.0
        text_lower = config_text.lower()
        if re.search(r'\b(hostname|sysname|appliance-name)\b', text_lower):
            completeness_pts += 0.3
        if re.search(r'\b(interface|edit port|set interfaces)\b', text_lower):
            completeness_pts += 0.4
        if re.search(r'\b(ip route|router|firewall|line vty|system services|snmp|logging)\b', text_lower):
            completeness_pts += 0.3
        breakdown['completeness'] = round(completeness_pts, 2)
        if completeness_pts < 0.4:
            reasons.append('Configuration lacks structural blocks (no hostname or interfaces)')

        v_conf = max(0.0, min(1.0, float(vendor_confidence)))
        breakdown['vendor_confidence'] = v_conf
        if v_conf < 0.3:
            reasons.append(f'Low vendor identification confidence ({v_conf:.2f})')

        sec_features = 0.0
        if re.search(r'\b(ssh|telnet|http|https|transport input)\b', text_lower):
            sec_features += 0.25
        if re.search(r'\b(logging|syslog|info-center)\b', text_lower):
            sec_features += 0.25
        if re.search(r'\b(ntp|ntp-service|time-server)\b', text_lower):
            sec_features += 0.25
        if re.search(r'\b(access-list|acl|firewall|rulebase|crypto|ipsec|aaa)\b', text_lower):
            sec_features += 0.25
        breakdown['security_content'] = round(sec_features, 2)

        unredacted = 0
        if re.search(r'password\s+[a-zA-Z0-9!@#$%^&*]{6,}', text_lower) and not '<redacted>' in text_lower:
            unredacted += 1
        secret_score = 0.5 if unredacted > 0 else 1.0
        breakdown['secret_redaction'] = secret_score

        total_score = (
            breakdown['no_corruption'] * 0.15 +
            breakdown['parseability'] * 0.20 +
            breakdown['completeness'] * 0.20 +
            breakdown['vendor_confidence'] * 0.15 +
            breakdown['security_content'] * 0.20 +
            breakdown['secret_redaction'] * 0.10
        )
        total_score = round(total_score, 4)

        if total_score >= 0.75:
            tier = 'HIGH QUALITY'
            status = 'PROCESSED'
        elif total_score >= 0.40:
            tier = 'MEDIUM QUALITY'
            status = 'PROCESSED'
        elif total_score >= 0.10:
            tier = 'LOW QUALITY'
            status = 'PROCESSED'
            reasons.append('Marginal configuration quality; retained with audit flags')
        else:
            tier = 'REJECTED'
            status = 'REJECTED'
            reasons.append('Configuration score below acceptance threshold')

        config_hash = hashlib.sha256(config_text.encode('utf-8', 'replace')).hexdigest()[:16]
        normalized_hash = hashlib.sha256(re.sub(r'\s+', ' ', config_text.strip()).encode('utf-8', 'replace')).hexdigest()[:16]

        return QualityAssessment(
            source_file_id=file_id,
            vendor=vendor,
            platform=platform,
            configuration_hash=config_hash,
            normalized_hash=normalized_hash,
            dataset_version=dataset_version,
            processing_status=status,
            quality_score=total_score,
            quality_tier=tier,
            reasons=reasons,
            breakdown=breakdown
        )

quality_scorer = DataQualityScorer()
