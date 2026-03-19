"""
Tests for Web API (Faz 4).
Tests cover: analysis_manager, case_store, models, API endpoints.
"""

import json
import pytest
from pathlib import Path

from src.web.analysis_manager import AnalysisManager
from src.web.case_store import CaseStore
from src.web.models import (
    IOCRequest, IOCType, AnalysisState, Verdict,
    CaseCreate, CaseStatus, CaseNote, DashboardStats,
    FileUploadResponse,
)


# ========== Analysis Manager ==========

class TestAnalysisManager:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        db = str(tmp_path / 'test_jobs.db')
        self.mgr = AnalysisManager(db_path=db)

    def test_create_job(self):
        job_id = self.mgr.create_job('ioc', {'value': '8.8.8.8'})
        assert len(job_id) == 12
        job = self.mgr.get_job(job_id)
        assert job is not None
        assert job['status'] == 'queued'
        assert job['analysis_type'] == 'ioc'

    def test_get_nonexistent_job(self):
        assert self.mgr.get_job('nonexistent') is None

    def test_update_progress(self):
        job_id = self.mgr.create_job('file', {'sha256': 'abc'})
        self.mgr.update_progress(job_id, 50, 'Scanning with YARA...')
        job = self.mgr.get_job(job_id)
        assert job['status'] == 'running'
        assert job['progress'] == 50
        assert job['current_step'] == 'Scanning with YARA...'

    def test_complete_job(self):
        job_id = self.mgr.create_job('ioc', {'value': 'evil.com'})
        result = {'verdict': 'MALICIOUS', 'score': 85}
        self.mgr.complete_job(job_id, result, verdict='MALICIOUS', score=85)
        job = self.mgr.get_job(job_id)
        assert job['status'] == 'completed'
        assert job['progress'] == 100
        assert job['verdict'] == 'MALICIOUS'
        assert job['score'] == 85
        assert job['result'] == result

    def test_fail_job(self):
        job_id = self.mgr.create_job('ioc', {'value': 'test'})
        self.mgr.fail_job(job_id, 'API timeout')
        job = self.mgr.get_job(job_id)
        assert job['status'] == 'failed'
        assert 'timeout' in job['current_step']

    def test_list_jobs(self):
        self.mgr.create_job('ioc', {'v': '1'})
        self.mgr.create_job('file', {'v': '2'})
        self.mgr.create_job('email', {'v': '3'})
        jobs = self.mgr.list_jobs()
        assert len(jobs) == 3

    def test_list_jobs_with_status_filter(self):
        j1 = self.mgr.create_job('ioc', {'v': '1'})
        j2 = self.mgr.create_job('ioc', {'v': '2'})
        self.mgr.complete_job(j1, {}, verdict='CLEAN', score=5)
        queued = self.mgr.list_jobs(status='queued')
        completed = self.mgr.list_jobs(status='completed')
        assert len(queued) == 1
        assert len(completed) == 1

    def test_get_stats(self):
        j1 = self.mgr.create_job('ioc', {'v': '1'})
        j2 = self.mgr.create_job('ioc', {'v': '2'})
        j3 = self.mgr.create_job('ioc', {'v': '3'})
        self.mgr.complete_job(j1, {}, verdict='MALICIOUS', score=90)
        self.mgr.complete_job(j2, {}, verdict='CLEAN', score=5)
        self.mgr.complete_job(j3, {}, verdict='SUSPICIOUS', score=55)
        stats = self.mgr.get_stats()
        assert stats['total_analyses'] == 3
        assert stats['malicious_count'] == 1
        assert stats['clean_count'] == 1
        assert stats['suspicious_count'] == 1

    def test_list_with_limit_offset(self):
        for i in range(10):
            self.mgr.create_job('ioc', {'v': str(i)})
        page1 = self.mgr.list_jobs(limit=3, offset=0)
        page2 = self.mgr.list_jobs(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0]['id'] != page2[0]['id']


# ========== Case Store ==========

class TestCaseStore:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        db = str(tmp_path / 'test_cases.db')
        self.store = CaseStore(db_path=db)

    def test_create_case(self):
        case_id = self.store.create_case('Phishing Investigation', 'Suspicious email', 'high')
        assert len(case_id) == 12
        case = self.store.get_case(case_id)
        assert case is not None
        assert case['title'] == 'Phishing Investigation'
        assert case['severity'] == 'high'
        assert case['status'] == 'Open'

    def test_get_nonexistent_case(self):
        assert self.store.get_case('nonexistent') is None

    def test_list_cases(self):
        self.store.create_case('Case 1')
        self.store.create_case('Case 2')
        cases = self.store.list_cases()
        assert len(cases) == 2

    def test_update_status(self):
        case_id = self.store.create_case('Test')
        ok = self.store.update_case_status(case_id, 'Investigating')
        assert ok is True
        case = self.store.get_case(case_id)
        assert case['status'] == 'Investigating'

    def test_update_nonexistent_returns_false(self):
        ok = self.store.update_case_status('nonexistent', 'Closed')
        assert ok is False

    def test_link_analysis(self):
        case_id = self.store.create_case('Test')
        ok = self.store.link_analysis(case_id, 'analysis123')
        assert ok is True
        case = self.store.get_case(case_id)
        assert len(case['analyses']) == 1
        assert case['analyses'][0]['analysis_id'] == 'analysis123'

    def test_add_note(self):
        case_id = self.store.create_case('Test')
        note_id = self.store.add_note(case_id, 'Found malware sample', 'john')
        assert len(note_id) == 10
        case = self.store.get_case(case_id)
        assert len(case['notes']) == 1
        assert case['notes'][0]['content'] == 'Found malware sample'
        assert case['notes'][0]['author'] == 'john'

    def test_multiple_notes(self):
        case_id = self.store.create_case('Test')
        self.store.add_note(case_id, 'Note 1')
        self.store.add_note(case_id, 'Note 2')
        self.store.add_note(case_id, 'Note 3')
        case = self.store.get_case(case_id)
        assert len(case['notes']) == 3

    def test_list_with_counts(self):
        case_id = self.store.create_case('Test')
        self.store.link_analysis(case_id, 'a1')
        self.store.link_analysis(case_id, 'a2')
        self.store.add_note(case_id, 'note1')
        cases = self.store.list_cases()
        assert cases[0]['analysis_count'] == 2
        assert cases[0]['note_count'] == 1


# ========== Pydantic Models ==========

class TestModels:
    def test_ioc_request(self):
        req = IOCRequest(value='8.8.8.8', ioc_type=IOCType.IP)
        assert req.value == '8.8.8.8'
        assert req.ioc_type == IOCType.IP

    def test_ioc_request_auto_type(self):
        req = IOCRequest(value='evil.com')
        assert req.ioc_type is None

    def test_file_upload_response(self):
        resp = FileUploadResponse(
            analysis_id='abc123',
            filename='malware.exe',
            sha256='deadbeef' * 8,
        )
        assert resp.status == AnalysisState.QUEUED

    def test_case_create(self):
        case = CaseCreate(title='Test', severity='high')
        assert case.title == 'Test'
        assert case.severity == 'high'

    def test_case_note(self):
        note = CaseNote(content='Important finding')
        assert note.author == 'analyst'

    def test_dashboard_stats_defaults(self):
        stats = DashboardStats()
        assert stats.total_analyses == 0
        assert stats.average_score == 0.0

    def test_verdict_enum(self):
        assert Verdict.MALICIOUS.value == 'MALICIOUS'
        assert Verdict.CLEAN.value == 'CLEAN'

    def test_case_status_enum(self):
        assert CaseStatus.OPEN.value == 'Open'
        assert CaseStatus.CLOSED.value == 'Closed'


# ========== FastAPI App Integration ==========

class TestFastAPIEndpoints:
    """Test API endpoints using TestClient."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test client with temp databases."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi not installed")

        from src.web.app import create_app

        self.app = create_app()
        # Override with temp DBs
        self.app.state.analysis_manager = AnalysisManager(
            db_path=str(tmp_path / 'jobs.db')
        )
        self.app.state.case_store = CaseStore(
            db_path=str(tmp_path / 'cases.db')
        )
        self.client = TestClient(self.app)

    def test_health_check(self):
        r = self.client.get('/api/config/health')
        assert r.status_code == 200
        data = r.json()
        assert data['status'] == 'healthy'

    def test_system_info(self):
        r = self.client.get('/api/config/info')
        assert r.status_code == 200
        assert 'Blue Team Assistant' in r.json()['app']

    def test_tool_status(self):
        r = self.client.get('/api/config/tools')
        assert r.status_code == 200
        assert 'tools' in r.json()

    def test_analyze_ioc(self):
        r = self.client.post('/api/analysis/ioc', json={
            'value': '8.8.8.8', 'ioc_type': 'ip'
        })
        assert r.status_code == 200
        data = r.json()
        assert 'analysis_id' in data
        assert data['status'] == 'queued'

    def test_get_analysis(self):
        # Create first
        r = self.client.post('/api/analysis/ioc', json={'value': 'evil.com'})
        aid = r.json()['analysis_id']
        # Get
        r2 = self.client.get(f'/api/analysis/{aid}')
        assert r2.status_code == 200
        assert r2.json()['analysis_type'] == 'ioc'

    def test_get_analysis_status(self):
        r = self.client.post('/api/analysis/ioc', json={'value': 'test'})
        aid = r.json()['analysis_id']
        r2 = self.client.get(f'/api/analysis/{aid}/status')
        assert r2.status_code == 200
        # Background thread may have already started so status could be
        # queued, running, completed, or failed.
        assert r2.json()['status'] in ('queued', 'running', 'completed', 'failed')

    def test_analysis_not_found(self):
        r = self.client.get('/api/analysis/nonexistent')
        assert r.status_code == 404

    def test_dashboard_stats(self):
        r = self.client.get('/api/dashboard/stats')
        assert r.status_code == 200

    def test_dashboard_recent(self):
        r = self.client.get('/api/dashboard/recent')
        assert r.status_code == 200
        assert 'items' in r.json()

    def test_dashboard_sources(self):
        r = self.client.get('/api/dashboard/sources')
        assert r.status_code == 200
        assert 'sources' in r.json()

    def test_create_case(self):
        r = self.client.post('/api/cases', json={
            'title': 'Test Case', 'severity': 'high'
        })
        assert r.status_code == 200
        assert 'id' in r.json()

    def test_list_cases(self):
        self.client.post('/api/cases', json={'title': 'C1'})
        self.client.post('/api/cases', json={'title': 'C2'})
        r = self.client.get('/api/cases')
        assert r.status_code == 200
        assert len(r.json()['items']) == 2

    def test_get_case(self):
        r = self.client.post('/api/cases', json={'title': 'Test'})
        cid = r.json()['id']
        r2 = self.client.get(f'/api/cases/{cid}')
        assert r2.status_code == 200
        assert r2.json()['title'] == 'Test'

    def test_case_not_found(self):
        r = self.client.get('/api/cases/nonexistent')
        assert r.status_code == 404

    def test_update_case_status(self):
        r = self.client.post('/api/cases', json={'title': 'Test'})
        cid = r.json()['id']
        r2 = self.client.patch(f'/api/cases/{cid}/status', json={'status': 'Investigating'})
        assert r2.status_code == 200

    def test_add_case_note(self):
        r = self.client.post('/api/cases', json={'title': 'Test'})
        cid = r.json()['id']
        r2 = self.client.post(f'/api/cases/{cid}/notes', json={
            'content': 'Important finding', 'author': 'analyst'
        })
        assert r2.status_code == 200
        assert 'id' in r2.json()

    def test_report_json(self):
        # Create and complete a job
        r = self.client.post('/api/analysis/ioc', json={'value': 'test'})
        aid = r.json()['analysis_id']
        mgr = self.app.state.analysis_manager
        mgr.complete_job(aid, {'verdict': 'CLEAN'}, verdict='CLEAN', score=5)
        r2 = self.client.get(f'/api/reports/{aid}/json')
        assert r2.status_code == 200

    def test_report_mitre_layer(self):
        # Create job directly (not via POST which spawns a bg thread that
        # may race and overwrite our result).
        mgr = self.app.state.analysis_manager
        aid = mgr.create_job('ioc', {'value': 'test'})
        mgr.complete_job(aid, {'mitre_techniques': [
            {'technique_id': 'T1059', 'tactic': 'Execution', 'technique_name': 'Scripting'}
        ]}, verdict='SUSPICIOUS', score=50)
        r2 = self.client.get(f'/api/reports/{aid}/mitre')
        assert r2.status_code == 200
        layer = r2.json()
        assert len(layer['techniques']) == 1

    def test_file_upload(self):
        import io
        file_content = b'MZ' + b'\x00' * 100
        r = self.client.post(
            '/api/analysis/file',
            files={'file': ('test.exe', io.BytesIO(file_content), 'application/octet-stream')},
        )
        assert r.status_code == 200
        data = r.json()
        assert 'analysis_id' in data
        assert data['filename'] == 'test.exe'
        assert len(data['sha256']) == 64
