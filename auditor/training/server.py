import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib

from ..models.baseline import SecurityBaselineModel
from ..parsers import registry
from ..parsers.llm.parser import LLMParser
from ..parsers.llm.client import AnthropicClient
from .mappings import (
    LearnedMapping,
    LearnedMappingStore,
    get_unrecognized_lines,
    get_llm_calls_avoided,
)

# Store HTML in a constant for a self-contained single-file server
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Training Dashboard</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #f8f9fa;
            color: #333;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: #1a202c;
            color: white;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            margin: 0;
            font-size: 1.5rem;
        }
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .metric-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
            border-top: 4px solid #4299e1;
        }
        .metric-card.avoided { border-top-color: #48bb78; }
        .metric-card.pending { border-top-color: #ecc94b; }
        .metric-card.conflicting { border-top-color: #f56565; }
        .metric-value {
            font-size: 2rem;
            font-weight: bold;
            margin: 0.5rem 0 0 0;
        }
        .metric-label {
            color: #718096;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .main-layout {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
        }
        @media (max-width: 900px) {
            .main-layout {
                grid-template-columns: 1fr;
            }
        }
        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        .card-title {
            margin-top: 0;
            margin-bottom: 1.5rem;
            font-size: 1.25rem;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 0.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            font-size: 0.875rem;
        }
        .form-control {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #cbd5e0;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .btn {
            background-color: #4299e1;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
        }
        .btn:hover { background-color: #3182ce; }
        .btn-success { background-color: #48bb78; }
        .btn-success:hover { background-color: #38a169; }
        .btn-danger { background-color: #e53e3e; }
        .btn-danger:hover { background-color: #c53030; }
        .btn-secondary { background-color: #718096; }
        .btn-secondary:hover { background-color: #4a5568; }
        
        .line-list {
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            margin-bottom: 1rem;
        }
        .line-item {
            padding: 0.75rem;
            border-bottom: 1px solid #e2e8f0;
            cursor: pointer;
            font-family: monospace;
            background-color: #fff;
            display: flex;
            justify-content: space-between;
        }
        .line-item:hover {
            background-color: #edf2f7;
        }
        .line-item.selected {
            background-color: #ebf8ff;
            border-left: 4px solid #4299e1;
        }
        .mapping-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }
        .mapping-table th, .mapping-table td {
            text-align: left;
            padding: 0.75rem;
            border-bottom: 1px solid #e2e8f0;
        }
        .mapping-table th {
            background-color: #f7fafc;
            font-weight: 600;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            font-weight: bold;
            border-radius: 9999px;
        }
        .badge-approved { background-color: #c6f6d5; color: #22543d; }
        .badge-pending { background-color: #feebc8; color: #744210; }
        .badge-conflicting { background-color: #fed7d7; color: #742a2a; }
        .badge-disabled { background-color: #edf2f7; color: #4a5568; }
        .badge-deleted { background-color: #e2e8f0; color: #1a202c; }

        .ai-proposal-box {
            background-color: #ebf8ff;
            border: 1px solid #bee3f8;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .ai-proposal-title {
            font-weight: bold;
            color: #2b6cb0;
            margin-bottom: 0.5rem;
        }
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(0,0,0,.3);
            border-radius: 50%;
            border-top-color: #4299e1;
            animation: spin 1s ease-in-out infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Auditor — Administrator Training</h1>
        <div>v1.0.0</div>
    </div>
    
    <div class="container">
        <!-- Metrics -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value" id="metric-unknown">0</div>
                <div class="metric-label">Unknown Patterns</div>
            </div>
            <div class="metric-card pending">
                <div class="metric-value" id="metric-pending">0</div>
                <div class="metric-label">Awaiting Review</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="metric-approved">0</div>
                <div class="metric-label">Approved Mappings</div>
            </div>
            <div class="metric-card conflicting">
                <div class="metric-value" id="metric-conflicting">0</div>
                <div class="metric-label">Conflicts</div>
            </div>
            <div class="metric-card avoided">
                <div class="metric-value" id="metric-avoided">0</div>
                <div class="metric-label">LLM Calls Avoided</div>
            </div>
        </div>

        <div class="main-layout">
            <!-- Left Column: Upload & Training -->
            <div>
                <div class="card">
                    <h2 class="card-title">1. Upload Configuration File</h2>
                    <div class="form-group">
                        <input type="file" id="config-file-input" class="form-control">
                    </div>
                    <button class="btn" id="upload-btn">Upload & Scan</button>
                    
                    <div id="scan-results" style="display:none; margin-top: 1.5rem;">
                        <h3>Scan Findings</h3>
                        <p><strong>Detected Vendor:</strong> <span id="detected-vendor">Unknown</span></p>
                        <p>Select an unrecognized line below to teach the system:</p>
                        <div class="line-list" id="unrecognized-lines-list"></div>
                    </div>
                </div>

                <div class="card" id="training-card" style="display:none;">
                    <h2 class="card-title">2. Map Configuration Pattern</h2>
                    
                    <div id="ai-proposal-section" style="display:none;">
                        <div class="ai-proposal-box">
                            <div class="ai-proposal-title">AI Suggested Interpretation</div>
                            <div id="ai-proposal-content">Proposing mapping...</div>
                        </div>
                    </div>

                    <form id="mapping-form">
                        <input type="hidden" id="form-mapping-id">
                        <div class="form-group">
                            <label>Raw Configuration Line</label>
                            <input type="text" id="form-raw-line" class="form-control" readonly>
                        </div>
                        <div class="form-group">
                            <label>Pattern (exact line prefix or regex match)</label>
                            <input type="text" id="form-pattern" class="form-control" placeholder="e.g. set admin-https-ssl-versions">
                        </div>
                        <div class="form-group">
                            <label>Normalized Baseline Field</label>
                            <select id="form-field" class="form-control"></select>
                        </div>
                        <div class="form-group">
                            <label>Extraction Strategy</label>
                            <select id="form-strategy" class="form-control">
                                <option value="exact">Exact Presence (Boolean True)</option>
                                <option value="token">Token Extraction (extract value after pattern)</option>
                                <option value="token_list">Token-list Extraction (extract space-separated list)</option>
                                <option value="regex">Regex Extraction (Regex pattern match)</option>
                            </select>
                        </div>
                        <div class="form-group" id="regex-pattern-group" style="display:none;">
                            <label>Regex Pattern (with one capture group, e.g. set timeout (\d+))</label>
                            <input type="text" id="form-regex-pattern" class="form-control">
                        </div>
                        <div class="form-group">
                            <label>Compliance Relevance / Category</label>
                            <select id="form-compliance" class="form-control">
                                <option value="Cryptographic Protocol Security">Cryptographic Protocol Security</option>
                                <option value="Management Plane Access Control">Management Plane Access Control</option>
                                <option value="Password Strength & Hashing">Password Strength & Hashing</option>
                                <option value="AAA Authentication">AAA Authentication</option>
                                <option value="System Monitoring & Logging">System Monitoring & Logging</option>
                                <option value="NTP Clock Synchronization">NTP Clock Synchronization</option>
                            </select>
                        </div>
                        <div style="display:flex; gap: 1rem;">
                            <button type="submit" class="btn btn-success" id="save-btn">Save Approved Rule</button>
                            <button type="button" class="btn btn-danger" id="reject-btn">Reject Suggestion</button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Right Column: Rules Management -->
            <div>
                <div class="card">
                    <h2 class="card-title">Learned Mappings Store</h2>
                    <div style="overflow-x:auto;">
                        <table class="mapping-table">
                            <thead>
                                <tr>
                                    <th>Pattern</th>
                                    <th>Field</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="mappings-table-body">
                                <tr><td colspan="4">Loading mappings...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let fields = [];
        let unrecognizedLines = [];
        let detectedVendor = 'fortios';
        let detectedOS = 'unknown';

        // Load Baseline Fields
        async function loadFields() {
            const res = await fetch('/api/fields');
            fields = await res.json();
            const select = document.getElementById('form-field');
            select.innerHTML = fields.map(f => `<option value="${f}">${f}</option>`).join('');
        }

        // Load Metrics & Mappings
        async function loadDashboard() {
            const mRes = await fetch('/api/metrics');
            const metrics = await mRes.json();
            document.getElementById('metric-unknown').innerText = metrics.unknown_patterns;
            document.getElementById('metric-pending').innerText = metrics.awaiting_review;
            document.getElementById('metric-approved').innerText = metrics.approved_mappings;
            document.getElementById('metric-conflicting').innerText = metrics.conflicting;
            document.getElementById('metric-avoided').innerText = metrics.llm_calls_avoided;

            const mapRes = await fetch('/api/mappings');
            const mappings = await mapRes.json();
            const tbody = document.getElementById('mappings-table-body');
            
            if (mappings.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4">No mappings defined yet.</td></tr>';
                return;
            }
            
            tbody.innerHTML = mappings.map(m => `
                <tr style="${m.status === 'deleted' ? 'display:none;' : ''}">
                    <td><strong>${m.pattern}</strong><br><small style="color:gray">${m.vendor}</small></td>
                    <td><code>${m.field}</code><br><small style="color:gray">${m.extraction_strategy}</small></td>
                    <td><span class="badge badge-${m.status}">${m.status}</span></td>
                    <td>
                        <div style="display:flex; gap:0.25rem;">
                            ${m.status !== 'approved' ? `<button class="btn btn-success" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="approveMapping('${m.mapping_id}')">Approve</button>` : ''}
                            ${m.status === 'approved' ? `<button class="btn btn-secondary" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="disableMapping('${m.mapping_id}')">Disable</button>` : ''}
                            <button class="btn btn-danger" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="deleteMapping('${m.mapping_id}')">Delete</button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        // Show/hide regex input
        document.getElementById('form-strategy').addEventListener('change', (e) => {
            const regexGroup = document.getElementById('regex-pattern-group');
            if (e.target.value === 'regex') {
                regexGroup.style.display = 'block';
            } else {
                regexGroup.style.display = 'none';
            }
        });

        // Upload config
        document.getElementById('upload-btn').addEventListener('click', async () => {
            const fileInput = document.getElementById('config-file-input');
            if (!fileInput.files[0]) {
                alert('Please select a configuration file first.');
                return;
            }
            const formData = new FormData();
            formData.append('config', fileInput.files[0]);
            
            const res = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            
            detectedVendor = data.vendor;
            detectedOS = data.os_family;
            unrecognizedLines = data.unrecognized_lines;
            
            document.getElementById('detected-vendor').innerText = `${data.vendor} (${data.os_family})`;
            document.getElementById('scan-results').style.display = 'block';
            
            const list = document.getElementById('unrecognized-lines-list');
            if (unrecognizedLines.length === 0) {
                list.innerHTML = '<div style="padding:1rem; color:green;">No unrecognized lines detected! Entire config is understood by the parser.</div>';
            } else {
                list.innerHTML = unrecognizedLines.map(line => `
                    <div class="line-item" onclick="selectLine(${line.line_number}, '${escapeHtml(line.text)}')">
                        <span>L${line.line_number}: ${escapeHtml(line.text)}</span>
                        <span style="color:#4299e1; font-weight:bold;">Teach &raquo;</span>
                    </div>
                `).join('');
            }
        });

        function escapeHtml(text) {
            return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }

        // Select a line for training
        async function selectLine(lineNum, text) {
            // Highlight item
            const items = document.querySelectorAll('.line-item');
            items.forEach(item => item.classList.remove('selected'));
            event.currentTarget.classList.add('selected');

            document.getElementById('training-card').style.display = 'block';
            document.getElementById('form-mapping-id').value = 'LM-' + Math.floor(Math.random() * 10000);
            document.getElementById('form-raw-line').value = text;
            
            // Generate pattern suggestion
            document.getElementById('form-pattern').value = text.split(' ')[0] + ' ' + (text.split(' ')[1] || '');

            // Request AI interpretation
            document.getElementById('ai-proposal-section').style.display = 'block';
            document.getElementById('ai-proposal-content').innerHTML = '<div class="loading"></div> Requesting AI interpretation...';

            try {
                const res = await fetch('/api/propose', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ vendor: detectedVendor, os_family: detectedOS, line: text })
                });
                const suggestion = await res.json();
                
                document.getElementById('ai-proposal-content').innerHTML = `
                    <strong>Field:</strong> <code>${suggestion.field}</code><br>
                    <strong>Extracted Value:</strong> <code>${suggestion.value}</code><br>
                    <strong>Compliance Category:</strong> ${suggestion.compliance_relevance}<br>
                    <strong>Reasoning:</strong> ${suggestion.reasoning}
                `;

                // Fill form
                document.getElementById('form-field').value = suggestion.field;
                // Default to token strategy, but if value looks like boolean default to exact
                if (suggestion.value.toLowerCase() === 'true' || suggestion.value.toLowerCase() === 'false') {
                    document.getElementById('form-strategy').value = 'exact';
                } else {
                    document.getElementById('form-strategy').value = 'token';
                }
                document.getElementById('form-strategy').dispatchEvent(new Event('change'));

            } catch (e) {
                document.getElementById('ai-proposal-content').innerText = 'Failed to get AI suggestion. Please fill the mapping form manually.';
            }
        }

        // Mapping Form Submit
        document.getElementById('mapping-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const mapping = {
                mapping_id: document.getElementById('form-mapping-id').value,
                vendor: detectedVendor,
                os_family: detectedOS,
                pattern: document.getElementById('form-pattern').value,
                field: document.getElementById('form-field').value,
                extraction_strategy: document.getElementById('form-strategy').value,
                regex_pattern: document.getElementById('form-regex-pattern').value || null,
                compliance_control: document.getElementById('form-compliance').value,
                evidence_example: document.getElementById('form-raw-line').value,
                status: 'approved',
                approval_state: 'approved'
            };

            const res = await fetch('/api/mappings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(mapping)
            });

            if (res.ok) {
                alert('Mapping rule saved and approved successfully!');
                document.getElementById('training-card').style.display = 'none';
                loadDashboard();
            } else {
                const err = await res.json();
                alert('Error: ' + err.message);
            }
        });

        // Reject Suggestion
        document.getElementById('reject-btn').addEventListener('click', () => {
            document.getElementById('training-card').style.display = 'none';
            alert('Suggestion rejected.');
        });

        async function approveMapping(id) {
            await fetch('/api/mappings/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mapping_id: id })
            });
            loadDashboard();
        }

        async function disableMapping(id) {
            await fetch('/api/mappings/disable', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mapping_id: id })
            });
            loadDashboard();
        }

        async function deleteMapping(id) {
            if (confirm('Are you sure you want to delete this mapping rule?')) {
                await fetch('/api/mappings/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mapping_id: id })
                });
                loadDashboard();
            }
        }

        // Initialize
        loadFields();
        loadDashboard();
    </script>
</body>
</html>
"""


class TrainingHTTPHandler(BaseHTTPRequestHandler):
    store_path = Path("training/learned_mappings.jsonl")
    stats_path = Path("training/stats.json")
    llm_client: Optional[AnthropicClient] = None

    def __init__(self, *args, **kwargs):
        self.store = LearnedMappingStore(self.store_path)
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        # Prevent spamming stdout during tests
        pass

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/training":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
            return

        elif url.path == "/api/fields":
            fields = SecurityBaselineModel.observable_fields()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(fields).encode("utf-8"))
            return

        elif url.path == "/api/metrics":
            mappings = self.store.list_mappings()
            awaiting = len([m for m in mappings if m.status == "pending"])
            approved = len([m for m in mappings if m.status == "approved" or m.approval_state == "approved"])
            conflicting = len([m for m in mappings if m.status == "conflicting"])
            rejected = len([m for m in mappings if m.status == "rejected" or m.approval_state == "rejected"])
            
            metrics = {
                "unknown_patterns": awaiting + conflicting,
                "awaiting_review": awaiting,
                "approved_mappings": approved,
                "conflicting": conflicting,
                "rejected": rejected,
                "llm_calls_avoided": get_llm_calls_avoided(self.stats_path)
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(metrics).encode("utf-8"))
            return

        elif url.path == "/api/mappings":
            mappings = self.store.list_mappings()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            # serialize mappings
            payload = [m.model_dump(mode="json") for m in mappings]
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        if url.path == "/api/upload":
            # Very basic multipart/form-data boundary parsing to read file upload
            boundary = self.headers.get_content_type()
            # If standard multipart/form-data:
            content_str = body.decode("utf-8", errors="replace")
            # Pull the lines of config out
            lines = content_str.splitlines()
            config_lines = []
            in_file = False
            for line in lines:
                if "Content-Disposition" in line and "filename=" in line:
                    in_file = True
                    continue
                if in_file and line.startswith("------WebKitFormBoundary") or in_file and line.startswith("------"):
                    break
                if in_file:
                    # Skip empty headers
                    if not line.strip() and len(config_lines) == 0:
                        continue
                    config_lines.append(line)
            
            config_text = "\n".join(config_lines).strip()
            if not config_text:
                # If multipart parse failed, try raw body
                config_text = content_str.strip()

            try:
                parser_cls, confidence = registry.detect(config_text, allow_fallback=False)
            except Exception:
                parser_cls = LLMParser

            parser = parser_cls()
            try:
                baseline = parser.parse(config_text)
                unrecognized = get_unrecognized_lines(config_text, baseline)
                vendor = baseline.provenance.vendor
                os_family = baseline.provenance.os_family
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"message": f"Parse error: {e}"}).encode("utf-8"))
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "vendor": vendor,
                "os_family": os_family,
                "unrecognized_lines": unrecognized
            }).encode("utf-8"))
            return

        elif url.path == "/api/propose":
            try:
                data = json.loads(body.decode("utf-8"))
                vendor = data["vendor"]
                os_family = data["os_family"]
                line = data["line"]
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                return

            client = self.llm_client or AnthropicClient()
            try:
                proposal = client.propose_mapping(vendor, os_family, line)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(proposal).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"message": str(e)}).encode("utf-8"))
            return

        elif url.path == "/api/mappings":
            try:
                data = json.loads(body.decode("utf-8"))
                mapping = LearnedMapping.model_validate(data)
                saved = self.store.create_mapping(mapping)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(saved.model_dump(mode="json")).encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"message": str(e)}).encode("utf-8"))
            return

        elif url.path == "/api/mappings/approve":
            try:
                data = json.loads(body.decode("utf-8"))
                mid = data["mapping_id"]
                saved = self.store.approve_mapping(mid)
                self.send_response(200)
                self.end_headers()
            except Exception as e:
                self.send_response(400)
                self.end_headers()
            return

        elif url.path == "/api/mappings/disable":
            try:
                data = json.loads(body.decode("utf-8"))
                mid = data["mapping_id"]
                saved = self.store.disable_mapping(mid)
                self.send_response(200)
                self.end_headers()
            except Exception as e:
                self.send_response(400)
                self.end_headers()
            return

        elif url.path == "/api/mappings/delete":
            try:
                data = json.loads(body.decode("utf-8"))
                mid = data["mapping_id"]
                saved = self.store.delete_mapping(mid)
                self.send_response(200)
                self.end_headers()
            except Exception as e:
                self.send_response(400)
                self.end_headers()
            return

        self.send_error(404, "Not Found")


def run_server(port: int = 8080, store_path: Optional[Path] = None, stats_path: Optional[Path] = None, llm_client: Optional[Any] = None) -> None:
    if store_path:
        TrainingHTTPHandler.store_path = Path(store_path)
    if stats_path:
        TrainingHTTPHandler.stats_path = Path(stats_path)
    if llm_client:
        TrainingHTTPHandler.llm_client = llm_client

    server_address = ("", port)
    httpd = HTTPServer(server_address, TrainingHTTPHandler)
    print(f"Training UI server running on http://localhost:{port}/training")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
