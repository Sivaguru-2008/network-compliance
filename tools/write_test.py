import pytest
from fastapi.testclient import TestClient
from auditor.adapters import (
    adapter_registry, CiscoIOSAdapter, JuniperJunosAdapter, FortiOSAdapter,
    PaloAltoPANOSAdapter, MikroTikRouterOSAdapter, BarracudaCloudGenAdapter
)
from nlp_pipeline.quality import quality_scorer, QualityAssessment
from nlp_pipeline.qa_engine import qa_engine
from nlp_pipeline.taxonomy import SecurityFinding, merge_findings, calculate_risk_score
from auditor.web.app import app


class TestVendorAdapters:
    def test_cisco_adapter(self):
        adapter = CiscoIOSAdapter()
        assert adapter.vendor_slug == 'cisco'
        assert adapter.platform == 'cisco_ios'
        assert adapter.corpus_status == 'SUPPORTED'

        config = 'hostname R1\ninterface GigabitEthernet0/0\nip address 10.0.0.1 255.255.255.0\nline vty 0 4\ntransport input ssh\nexit\n'
        secs = adapter.extract_sections(config)
        assert 'INTERFACE' in secs
        feats = adapter.extract_security_features(config)
        assert feats.get('ssh_enabled', {}).get('value') is True
        assert feats.get('telnet_enabled', {}).get('value') is False

        ents = adapter.extract_entities(config)
        ips_found = [u.get('value') for u in ents if u.get('type') == 'IP_ADDRESS']
        assert '10.0.0.1' in ips_found

    def test_limited_corpus_status(self):
        adapter = BarracudaCloudGenAdapter()
        assert adapter.corpus_status == 'SUPPORTED_WITH_LIMITED_CORPUS'

    def test_registry_ranking(self):
        config = 'set system host-name fw\nset system services ssh\n'
        ranked = adapter_registry.rank(config)
        assert len(ranked) > 0
        top = ranked[0][1]
        assert isinstance(top, JuniperJunosAdapter)


class TestDataQualityScoring:
    def test_high_quality_config(self):
        config = 'hostname USA-CORE-01\ninterface Gig0/0\nip address 192.168.1.1 255.255.255.0\nip route 0.0.0.0 0.0.0.0 192.168.1.254\nline vty 0 4\ntransport input ssh\nlogging 10.0.0.5\nntp server 10.0.0.1\naccess-list 101 permit tcp 192.168.1.0 0.0.0.255 any eq 443\nexit\n'
        res = quality_scorer.score_configuration(config, file_id='cg01', vendor='cisco', platform='cisco_ios', vendor_confidence=1.0)
        assert res.quality_tier == 'HIGH QUALITY'
        assert res.processing_status == 'PROCESSED'
        assert res.quality_score >= 0.75

    def test_rejected_empty_config(self):
        res = quality_scorer.score_configuration('   \n  ', file_id='cg22')
        assert res.quality_tier == 'REJECTED'
        assert res.processing_status == 'REJECTED'
        assert 'Empty configuration text' in res.reasons

    def test_rejected_corrupt_config(self):
        res = quality_scorer.score_configuration('<html><body>502 Bad Gateway</body></html>', file_id='cg33')
        assert res.quality_tier == 'REJECTED'
        assert res.processing_status == 'REJECTED'

    def test_low_quality_flagged_not_deleted(self):
        config = 'abc123\ndef456\nghi789\n'
        res = quality_scorer.score_configuration(config, file_id='cg44', vendor_confidence=0.1)
        assert res.quality_tier in ['LOW QUALITY', 'MEDIUM QUALITY', 'REJECTED']
        assert len(res.reasons) > 0


class TestGroundedQA:
    def test_qa_yes_answer(self):
        config = 'line vty 0 4\nweb-management https\ntransport input ssh\n'
        res = qa_engine.answer_question('Is SSH enabled?', config)
        assert res.answer == 'YES'
        assert len(res.evidence) > 0
        assert res.evidence[0]['line_start'] == 3

    def test_qa_no_answer(self):
        config = 'line vty 0 4\nweb-management https\ntransport input ssh\n'
        res = qa_engine.answer_question('Is Telnet enabled?', config)
        assert res.answer == 'NO'

    def test_qa_not_determinable(self):
        config = 'hostname R1'
        res = qa_engine.answer_question('What is the color of the router?', config)
        assert res.answer == 'NOT_DETERMINABLE'


class TestTaxonomyAndRiskScoring:
    def test_merge_duplicate_findings(self):
        f1 = SecurityFinding(finding_id='F1', finding_name='TELNET_ENABLED', severity='HIGH', category='remote_access', confidence=0.8, evidence=[{'line': 10}])
        f2 = SecurityFinding(finding_id='F2', finding_name='TELNET_ENABLED', severity='HIGH', category='remote_access', confidence=0.95, evidence=[{'line': 11}])
        merged = merge_findings([f1, f2])
        assert len(merged) == 1
        assert merged[0].confidence == 0.95
        assert len(merged[0].evidence) == 2

    def test_risk_score_calculation(self):
        fs = [
            SecurityFinding(finding_id='C1', finding_name='DEFAULT_CREDENTIAL', severity='CRITICAL', category='credential_security', confidence=1.0),
            SecurityFinding(finding_id='H1', finding_name='TELNET_ENABLED', severity='HIGH', category='remote_access', confidence=1.0),
            SecurityFinding(finding_id='M1', finding_name='LOGGING_DISABLED', severity='MEDIUM', category='logging', confidence=1.0),
        ]
        res = calculate_risk_score(fs)
        assert res['risk_score'] == 10 + 7 + 4  # 21
        assert res['finding_count'] == 3
        assert res['severity_distribution']['CRITICAL'] == 1


class TestRESTAPI:
    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_health(self, client):
        resp = client.get('/health')
        assert resp.status_code == 200
        data = resp.json()
        assert data['version'] == '2.2.0'
        assert data['status'] == 'ok'

    def test_qa_endpoint(self, client):
        resp = client.post('/qa', json={'question': 'Is SSH enabled?', 'config_text': 'line vty 0 4\ntransport input ssh\n'})
        assert resp.status_code == 200
        assert resp.json()['answer'] == 'YES'

    def test_analyze_endpoint(self, client):
        config = 'hostname R1\ninterface Gig0/0\nip address 10.0.0.1 255.255.255.0\nline vty 0 4\ntransport input ssh\n'
        resp = client.post('/analyze', json={'config_text': config})
        assert resp.status_code == 200
        data = resp.json()
        assert data['status'] == 'COMPLETED'
        assert 'findings' in data
