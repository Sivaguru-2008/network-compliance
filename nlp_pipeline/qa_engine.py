import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class QAEvidence:
    line_start: int
    line_end: int
    text: str


@dataclass
class QAResult:
    question: str
    answer: str
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ''
    matched_concept: str = ''


class GroundedSecurityQAEngine:
    INTENT_MAP = {
        'ssh': ('ssh_enabled', 'MANAGEMENT', ['transport input', 'ssh', 'set system services ssh', 'stelnet']),
        'telnet': ('telnet_enabled', 'MANAGEMENT', ['transport input', 'telnet', 'set system services telnet', 'service telnet']),
        'aaa': ('aaa_configured', 'AAA', ['aaa new-model', 'aaa authentication', 'set system authentication', 'radius-server', 'tacacs-server']),
        'tacacs': ('tacacs_configured', 'AAA', ['tacacs-server', 'tacacs', 'tacplus']),
        'radius': ('radius_configured', 'AAA', ['radius-server', 'radius']),
        'snmp': ('snmp_configured', 'SNMP', ['snmp-server', 'snmp-agent', 'set snmp', '/snmp']),
        'snmpv3': ('snmpv3_configured', 'SNMP', ['snmp-server group', 'snmp-server user', 'v3', 'usm']),
        'http': ('http_enabled', 'MANAGEMENT', ['ip http server', 'web-management http', 'protocol http', 'service http']),
        'https': ('https_enabled', 'MANAGEMENT', ['ip http secure-server', 'web-management https', 'protocol https', 'service https']),
        'logging': ('logging_configured', 'LOGGING', ['logging host', 'logging buffered', 'syslog host', 'info-center loghost', '/system logging']),
        'ntp': ('ntp_configured', 'NTP', ['ntp server', 'ntp-service', 'ntpserver', '/system ntp']),
        'weak crypto': ('weak_crypto', 'VPN', ['des', '3des', 'md5', 'rc4', 'diffie-hellman-group1', 'sha-1']),
        'crypto': ('weak_crypto', 'VPN', ['des', '3des', 'md5', 'rc4', 'diffie-hellman-group1', 'sha-1']),
        'acl': ('acls_present', 'FIREWALL', ['access-list', 'acl', 'firewall policy', 'rulebase', 'security policy']),
        'any to any': ('unrestricted_rules', 'FIREWALL', ['permit ip any any', 'permit any any', 'rule 10 permit ip']),
        'password encryption': ('password_encryption', 'AAA', ['service password-encryption', 'enable secret', 'secret 5', 'secret 9']),
    }

    def answer_question(self, question: str, config_text: str, vendor: str = 'unknown') -> QAResult:
        q_lower = question.lower().strip()
        matched_key = None

        for key in self.INTENT_MAP:
            if key in q_lower:
                matched_key = key
                break

        if not matched_key:
            return QAResult(
                question=question,
                answer='NOT_DETERMINABLE',
                confidence=0.50,
                evidence=[],
                reason='Question intent did not match any supported security control concepts.',
                matched_concept='unknown'
            )

        concept_id, category, patterns = self.INTENT_MAP[matched_key]
        lines = config_text.splitlines()

        matching_lines = []
        for i, line in enumerate(lines, 1):
            s = line.strip().lower()
            if not s or s.startswith(('!', '#', '//')):
                continue
            for pat in patterns:
                if pat in s:
                    matching_lines.append((i, line.strip()))
                    break

        if not matching_lines:
            return QAResult(
                question=question,
                answer='NO',
                confidence=0.90,
                evidence=[],
                reason=f'No configuration evidence found for {concept_id} (searched {len(lines)} lines).',
                matched_concept=concept_id
            )

        evidence_list = []
        for line_num, text in matching_lines[:5]:
            evidence_list.append({
                'line_start': line_num,
                'line_end': line_num,
                'text': text
            })

        primary_text = ' '.join([t for _, t in matching_lines]).lower()
        if 'no ' in primary_text or 'delete' in primary_text or 'undo' in primary_text or 'disabled' in primary_text:
            ans = 'NO'
            conf = 0.92
            reason = f'Configuration explicitly disables or negates {concept_id}.'
        else:
            ans = 'YES'
            conf = 0.95
            reason = f'Configuration contains active evidence for {concept_id}.'

        if matched_key == 'telnet':
            if 'transport input ssh' in primary_text and 'telnet' not in primary_text:
                ans = 'NO'
                reason = 'Management transport restricts access to SSH (Telnet disabled).'
            elif 'transport input telnet' in primary_text or 'telnet server enable' in primary_text:
                ans = 'YES'
                reason = 'Telnet is explicitly permitted in management transport settings.'

        return QAResult(
            question=question,
            answer=ans,
            confidence=conf,
            evidence=evidence_list,
            reason=reason,
            matched_concept=concept_id
        )

qa_engine = GroundedSecurityQAEngine()
