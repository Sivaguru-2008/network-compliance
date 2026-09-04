import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib
from datetime import datetime, timezone

from ..models.baseline import SecurityBaselineModel
from ..parsers import registry
from ..parsers.llm.parser import LLMParser, FIELD_TYPES
from ..parsers.llm.client import AnthropicClient, MockProvider, OpenAIProvider, GeminiProvider, redact_secrets
from ..parsers.hybrid import HybridParser
from .mappings import (
    LearnedMapping,
    LearnedMappingStore,
    get_unrecognized_lines,
    get_llm_calls_avoided,
)
from . import db
from ..pipeline import parse_config, evaluate, target_info, build_report
from ..ingest import record_from_audit
from ..report import write_device_pdf
from .. import __version__

# Self-contained SPA Dashboard HTML
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetAudit — Network Compliance Engine</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- FontAwesome for Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .sidebar-link.active {
            background-color: #2d3748;
            border-left: 4px solid #4299e1;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
    </style>
</head>
<body class="bg-gray-100 font-sans text-gray-800 flex h-screen overflow-hidden">

    <!-- Sidebar -->
    <div class="w-64 bg-gray-900 text-white flex flex-col justify-between flex-shrink-0">
        <div>
            <div class="p-5 flex items-center space-x-2 border-b border-gray-800">
                <i class="fa-solid fa-shield-halved text-blue-400 text-2xl"></i>
                <span class="text-xl font-bold tracking-wider text-blue-100">NetAudit</span>
            </div>
            <nav class="mt-5 space-y-1">
                <a href="#" onclick="switchTab('dashboard')" class="sidebar-link active block py-3 px-6 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 transition" id="link-dashboard">
                    <i class="fa-solid fa-chart-line w-5"></i>
                    <span>Dashboard</span>
                </a>
                <a href="#" onclick="switchTab('upload')" class="sidebar-link block py-3 px-6 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 transition" id="link-upload">
                    <i class="fa-solid fa-cloud-arrow-up w-5"></i>
                    <span>Upload Configs</span>
                </a>
                <a href="#" onclick="switchTab('devices')" class="sidebar-link block py-3 px-6 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 transition" id="link-devices">
                    <i class="fa-solid fa-server w-5"></i>
                    <span>Device Inventory</span>
                </a>
                <a href="#" onclick="switchTab('findings')" class="sidebar-link block py-3 px-6 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 transition" id="link-findings">
                    <i class="fa-solid fa-triangle-exclamation w-5"></i>
                    <span>Findings List</span>
                </a>
                <a href="#" onclick="switchTab('training')" class="sidebar-link block py-3 px-6 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 transition" id="link-training">
                    <i class="fa-solid fa-graduation-cap w-5"></i>
                    <span>AI Training Center</span>
                </a>
                <a href="#" onclick="switchTab('frameworks')" class="sidebar-link block py-3 px-6 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 transition" id="link-frameworks">
                    <i class="fa-solid fa-book-open w-5"></i>
                    <span>Framework Selection</span>
                </a>
                <a href="#" onclick="switchTab('reports')" class="sidebar-link block py-3 px-6 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 transition" id="link-reports">
                    <i class="fa-solid fa-file-pdf w-5"></i>
                    <span>Generated Reports</span>
                </a>
                <a href="#" onclick="switchTab('settings')" class="sidebar-link block py-3 px-6 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 transition" id="link-settings">
                    <i class="fa-solid fa-sliders w-5"></i>
                    <span>AI & Core Settings</span>
                </a>
            </nav>
        </div>
        <div class="p-4 border-t border-gray-800 text-xs text-gray-500 text-center">
            NetAudit Core v<span id="core-version">1.0.0</span>
        </div>
    </div>

    <!-- Main Content Area -->
    <div class="flex-1 flex flex-col overflow-hidden">
        
        <!-- Header -->
        <header class="bg-white shadow px-6 py-4 flex items-center justify-between border-b border-gray-200">
            <h2 class="text-xl font-semibold text-gray-800" id="current-page-title">Dashboard</h2>
            <div class="flex items-center space-x-4">
                <span class="text-sm bg-blue-100 text-blue-800 py-1 px-3 rounded-full font-medium" id="active-provider-badge">Provider: Mock</span>
            </div>
        </header>

        <!-- Dynamic Content Body -->
        <main class="flex-1 overflow-y-auto p-6 bg-gray-50">
            
            <!-- TAB: Dashboard -->
            <div id="tab-dashboard" class="tab-content active">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <!-- Metric Card 1 -->
                    <div class="bg-white p-6 rounded-lg shadow-sm border-t-4 border-blue-500">
                        <div class="flex justify-between items-center">
                            <div>
                                <p class="text-sm font-semibold text-gray-500 uppercase">Devices Audited</p>
                                <h3 class="text-3xl font-bold mt-2" id="stat-total-devices">0</h3>
                            </div>
                            <i class="fa-solid fa-network-wired text-3xl text-blue-400"></i>
                        </div>
                    </div>
                    <!-- Metric Card 2 -->
                    <div class="bg-white p-6 rounded-lg shadow-sm border-t-4 border-green-500">
                        <div class="flex justify-between items-center">
                            <div>
                                <p class="text-sm font-semibold text-gray-500 uppercase">Fully Compliant</p>
                                <h3 class="text-3xl font-bold mt-2 text-green-600" id="stat-compliant">0</h3>
                            </div>
                            <i class="fa-solid fa-circle-check text-3xl text-green-400"></i>
                        </div>
                    </div>
                    <!-- Metric Card 3 -->
                    <div class="bg-white p-6 rounded-lg shadow-sm border-t-4 border-red-500">
                        <div class="flex justify-between items-center">
                            <div>
                                <p class="text-sm font-semibold text-gray-500 uppercase">Non-Compliant</p>
                                <h3 class="text-3xl font-bold mt-2 text-red-600" id="stat-non-compliant">0</h3>
                            </div>
                            <i class="fa-solid fa-circle-xmark text-3xl text-red-400"></i>
                        </div>
                    </div>
                    <!-- Metric Card 4 -->
                    <div class="bg-white p-6 rounded-lg shadow-sm border-t-4 border-yellow-500">
                        <div class="flex justify-between items-center">
                            <div>
                                <p class="text-sm font-semibold text-gray-500 uppercase">Needs Review / Unknown</p>
                                <h3 class="text-3xl font-bold mt-2 text-yellow-600" id="stat-needs-review">0</h3>
                            </div>
                            <i class="fa-solid fa-triangle-exclamation text-3xl text-yellow-400"></i>
                        </div>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <!-- Framework Scores -->
                    <div class="bg-white rounded-lg shadow-sm p-6">
                        <h4 class="text-lg font-semibold text-gray-800 mb-4">Framework Rollup Summary</h4>
                        <div class="space-y-4" id="framework-scores-container">
                            <p class="text-gray-500">No framework results generated yet. Upload configurations to see analytics.</p>
                        </div>
                    </div>

                    <!-- General Stats -->
                    <div class="bg-white rounded-lg shadow-sm p-6 flex flex-col justify-between">
                        <div>
                            <h4 class="text-lg font-semibold text-gray-800 mb-4">Self-Adapting AI Metrics</h4>
                            <div class="space-y-3">
                                <div class="flex justify-between border-b border-gray-100 pb-2">
                                    <span class="text-gray-500">Approved Learned Mappings:</span>
                                    <span class="font-bold text-gray-800" id="stat-approved-mappings">0</span>
                                </div>
                                <div class="flex justify-between border-b border-gray-100 pb-2">
                                    <span class="text-gray-500">Pending Training Patterns:</span>
                                    <span class="font-bold text-gray-800" id="stat-unknown-patterns">0</span>
                                </div>
                                <div class="flex justify-between pb-2">
                                    <span class="text-gray-500">External LLM Calls Avoided (Cached):</span>
                                    <span class="font-bold text-green-600" id="stat-avoided-calls">0</span>
                                </div>
                            </div>
                        </div>
                        <div class="mt-6 p-4 bg-blue-50 border border-blue-100 rounded-lg flex items-start space-x-3">
                            <i class="fa-solid fa-circle-info text-blue-500 mt-1"></i>
                            <p class="text-xs text-blue-800 leading-relaxed">
                                NetAudit operates on a hybrid architecture. It first attempts deterministic parsing, then checks database mappings. If mapping fails, it sends configuration elements to the selected LLM (Gemini/OpenAI/Anthropic) to interpret configuration syntax without requiring manual system code updates.
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB: Upload -->
            <div id="tab-upload" class="tab-content">
                <div class="max-w-3xl mx-auto bg-white p-8 rounded-lg shadow-sm">
                    <h3 class="text-lg font-semibold text-gray-800 mb-6">Ingest Network Configurations</h3>
                    <form id="upload-config-form" class="space-y-6">
                        <!-- File Upload -->
                        <div class="border-2 border-dashed border-gray-300 rounded-lg p-8 flex flex-col items-center justify-center cursor-pointer hover:border-blue-500 transition bg-gray-50" onclick="document.getElementById('config-files').click()">
                            <i class="fa-solid fa-file-shield text-gray-400 text-4xl mb-4"></i>
                            <p class="text-gray-700 font-medium">Click to browse or drop configurations</p>
                            <p class="text-gray-400 text-xs mt-1">Supported extensions: .conf, .cfg, .config, .txt</p>
                            <input type="file" id="config-files" class="hidden" multiple accept=".conf,.cfg,.config,.txt">
                            <div class="mt-4 text-sm font-semibold text-blue-600" id="selected-files-list"></div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <!-- Force Vendor -->
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Force Parser (Optional)</label>
                                <select id="upload-vendor" class="w-full border border-gray-300 rounded-md p-2 shadow-sm focus:ring focus:ring-blue-200">
                                    <option value="">Auto-Detect Vendor (Recommended)</option>
                                    <option value="cisco_ios">Cisco IOS</option>
                                    <option value="juniper_junos">Juniper Junos</option>
                                    <option value="fortios">FortiOS</option>
                                    <option value="arista_eos">Arista EOS</option>
                                    <option value="sonic">SONiC Linux JSON</option>
                                </select>
                            </div>
                            <!-- Target Frameworks -->
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Frameworks to Evaluate</label>
                                <div class="flex flex-wrap gap-3 mt-1">
                                    <label class="inline-flex items-center"><input type="checkbox" value="CIS" checked class="form-checkbox text-blue-600 rounded"> <span class="ml-2 text-sm text-gray-700">CIS</span></label>
                                    <label class="inline-flex items-center"><input type="checkbox" value="NIST_800_53" class="form-checkbox text-blue-600 rounded"> <span class="ml-2 text-sm text-gray-700">NIST SP 800-53</span></label>
                                    <label class="inline-flex items-center"><input type="checkbox" value="STIG" class="form-checkbox text-blue-600 rounded"> <span class="ml-2 text-sm text-gray-700">DISA STIG</span></label>
                                    <label class="inline-flex items-center"><input type="checkbox" value="ISO_27001" class="form-checkbox text-blue-600 rounded"> <span class="ml-2 text-sm text-gray-700">ISO/IEC 27001</span></label>
                                </div>
                            </div>
                        </div>

                        <div class="flex justify-end pt-4">
                            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded shadow transition flex items-center space-x-2">
                                <i class="fa-solid fa-microchip"></i>
                                <span>Parse & Audit Configuration</span>
                            </button>
                        </div>
                    </form>
                    
                    <!-- Scan Progress / Result section -->
                    <div id="upload-scan-results" class="mt-8 border-t border-gray-100 pt-6 hidden">
                        <h4 class="font-bold text-gray-800 mb-4">Ingestion Results</h4>
                        <div id="upload-results-feed" class="space-y-4"></div>
                    </div>
                </div>
            </div>

            <!-- TAB: Devices -->
            <div id="tab-devices" class="tab-content">
                <div class="bg-white rounded-lg shadow-sm overflow-hidden">
                    <div class="p-6 border-b border-gray-100 flex justify-between items-center">
                        <h3 class="font-semibold text-gray-800 text-lg">Device Inventory</h3>
                        <div class="relative">
                            <input type="text" placeholder="Filter devices..." class="border border-gray-300 rounded-md py-1.5 pl-8 pr-4 text-sm w-64 shadow-sm" onkeyup="filterTable('devices-table', this.value)">
                            <i class="fa-solid fa-magnifying-glass absolute left-2.5 top-2.5 text-gray-400 text-xs"></i>
                        </div>
                    </div>
                    <table class="w-full border-collapse" id="devices-table">
                        <thead>
                            <tr class="bg-gray-50 border-b border-gray-100 text-gray-500 text-xs font-semibold text-left uppercase">
                                <th class="p-4">Hostname</th>
                                <th class="p-4">Vendor / OS</th>
                                <th class="p-4">Serial Number</th>
                                <th class="p-4">Audit Status</th>
                                <th class="p-4">Ingested At</th>
                                <th class="p-4 text-center">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100 text-sm" id="devices-list-container">
                            <!-- Async Load -->
                        </tbody>
                    </table>
                </div>

                <!-- Device Details Modal / Secondary page inside the tab -->
                <div id="device-details-pane" class="mt-8 bg-white rounded-lg shadow-sm p-6 hidden">
                    <div class="flex justify-between items-start border-b border-gray-100 pb-4 mb-6">
                        <div>
                            <h3 class="text-xl font-bold text-gray-800" id="details-device-title">Device Name</h3>
                            <p class="text-sm text-gray-500">Key ID: <code class="bg-gray-100 p-0.5 rounded" id="details-device-key">device_key</code></p>
                        </div>
                        <button onclick="document.getElementById('device-details-pane').classList.add('hidden')" class="text-gray-400 hover:text-gray-600 text-xl"><i class="fa-solid fa-xmark"></i></button>
                    </div>

                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <!-- Details Left: Specs -->
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <h4 class="font-semibold text-gray-700 mb-3 border-b pb-2 text-sm uppercase">Specifications</h4>
                            <div class="space-y-2 text-xs">
                                <div><span class="font-medium text-gray-500">Vendor:</span> <span id="details-vendor">cisco</span></div>
                                <div><span class="font-medium text-gray-500">OS Family:</span> <span id="details-os">ios</span></div>
                                <div><span class="font-medium text-gray-500">Serial:</span> <span id="details-serial">-</span></div>
                                <div><span class="font-medium text-gray-500">Hash:</span> <code id="details-hash">-</code></div>
                                <div><span class="font-medium text-gray-500">Source:</span> <span id="details-source">-</span></div>
                            </div>
                        </div>

                        <!-- Details Mid: Normalized baseline -->
                        <div class="lg:col-span-2 bg-white border rounded-lg overflow-hidden">
                            <h4 class="font-semibold text-gray-700 p-4 border-b text-sm uppercase">Normalized Baseline Posture</h4>
                            <div class="divide-y max-h-96 overflow-y-auto text-xs" id="details-baseline-fields"></div>
                        </div>
                    </div>

                    <!-- Findings Section -->
                    <div class="mt-8">
                        <h4 class="font-bold text-gray-800 mb-4 text-base">Control Findings & Remediation</h4>
                        <div class="space-y-4" id="details-device-findings"></div>
                    </div>
                </div>
            </div>

            <!-- TAB: Findings -->
            <div id="tab-findings" class="tab-content">
                <div class="bg-white rounded-lg shadow-sm overflow-hidden">
                    <div class="p-6 border-b border-gray-100 flex flex-col md:flex-row justify-between md:items-center gap-4">
                        <h3 class="font-semibold text-gray-800 text-lg">Compliance Findings Fleetwide</h3>
                        <div class="flex flex-wrap gap-3">
                            <select id="filter-findings-status" onchange="applyFindingsFilter()" class="border border-gray-300 rounded px-2 py-1 text-sm bg-white">
                                <option value="ALL">All Verdicts</option>
                                <option value="FAIL">FAIL</option>
                                <option value="NEEDS_REVIEW">NEEDS_REVIEW</option>
                                <option value="PASS">PASS</option>
                            </select>
                            <select id="filter-findings-severity" onchange="applyFindingsFilter()" class="border border-gray-300 rounded px-2 py-1 text-sm bg-white">
                                <option value="ALL">All Severities</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                            <input type="text" placeholder="Search..." class="border border-gray-300 rounded px-3 py-1 text-sm w-48 bg-white" onkeyup="filterTable('findings-table', this.value)">
                        </div>
                    </div>
                    <table class="w-full border-collapse" id="findings-table">
                        <thead>
                            <tr class="bg-gray-50 border-b border-gray-100 text-gray-500 text-xs font-semibold text-left uppercase">
                                <th class="p-4">Device</th>
                                <th class="p-4">Framework</th>
                                <th class="p-4">Control</th>
                                <th class="p-4">Verdict</th>
                                <th class="p-4">Severity</th>
                                <th class="p-4">Evidence</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100 text-sm" id="findings-list-container">
                            <!-- Async Load -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB: Training -->
            <div id="tab-training" class="tab-content">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <!-- Unknown Lines -->
                    <div class="bg-white p-6 rounded-lg shadow-sm">
                        <h3 class="font-semibold text-gray-800 text-lg border-b pb-3 mb-4">Unknown / Untrained Configurations</h3>
                        <p class="text-sm text-gray-500 mb-4">Select an unrecognized line below to teach the system how to interpret it:</p>
                        
                        <div class="border border-gray-200 rounded max-h-96 overflow-y-auto divide-y font-mono text-xs bg-gray-50" id="unknown-lines-feed">
                            <div class="p-4 text-center text-gray-400">Upload configuration files to scan for unrecognized command lines.</div>
                        </div>
                    </div>

                    <!-- AI Proposal & Training Form -->
                    <div class="bg-white p-6 rounded-lg shadow-sm hidden" id="training-form-card">
                        <h3 class="font-semibold text-gray-800 text-lg border-b pb-3 mb-4">Rule Configuration Mapping</h3>
                        
                        <!-- AI Suggestion -->
                        <div class="mb-4 bg-blue-50 border border-blue-200 rounded p-4 text-sm" id="proposal-box">
                            <div class="font-bold text-blue-800 flex items-center space-x-2">
                                <i class="fa-solid fa-wand-magic-sparkles"></i>
                                <span>AI Interpretation Suggestion</span>
                            </div>
                            <div class="mt-2 text-xs space-y-2 text-blue-900" id="proposal-content">
                                Extracting mapping suggestion...
                            </div>
                        </div>

                        <form id="training-form" class="space-y-4 text-sm">
                            <input type="hidden" id="train-mapping-id">
                            <div>
                                <label class="block font-medium text-gray-700 mb-1">Verbatim Command Line</label>
                                <input type="text" id="train-raw-line" class="w-full border p-2 rounded bg-gray-100 font-mono text-xs" readonly>
                            </div>
                            <div>
                                <label class="block font-medium text-gray-700 mb-1">Match Command Pattern</label>
                                <input type="text" id="train-pattern" class="w-full border p-2 rounded font-mono text-xs" placeholder="e.g. set system services ssh">
                            </div>
                            <div>
                                <label class="block font-medium text-gray-700 mb-1">Security Concept</label>
                                <input type="text" id="train-concept" class="w-full border p-2 rounded text-xs" placeholder="e.g. Session Idle Inactivity Timeout">
                            </div>
                            <div>
                                <label class="block font-medium text-gray-700 mb-1">Target Normalized Field</label>
                                <select id="train-field" class="w-full border p-2 rounded"></select>
                            </div>
                            <div>
                                <label class="block font-medium text-gray-700 mb-1">Extracted Value / Sample</label>
                                <input type="text" id="train-value" class="w-full border p-2 rounded font-mono text-xs" placeholder="e.g. 300, true, public">
                            </div>
                            <div>
                                <label class="block font-medium text-gray-700 mb-1">Value Extraction Strategy</label>
                                <select id="train-strategy" class="w-full border p-2 rounded" onchange="toggleRegexGroup()">
                                    <option value="exact">Exact Presence (Sets value to True)</option>
                                    <option value="token">Token Extraction (Reads first word after pattern)</option>
                                    <option value="token_list">Token List Extraction (Reads remainder as list)</option>
                                    <option value="regex">Regex Match Extraction (Requires capture group)</option>
                                </select>
                            </div>
                            <div id="train-regex-group" class="hidden">
                                <label class="block font-medium text-gray-700 mb-1">Regex Pattern (with one Capture Group)</label>
                                <input type="text" id="train-regex-pattern" class="w-full border p-2 rounded font-mono text-xs" placeholder="e.g. timeout (\d+)">
                            </div>
                            <div>
                                <label class="block font-medium text-gray-700 mb-1">Compliance Control Relevance</label>
                                <input type="text" id="train-relevance" class="w-full border p-2 rounded" placeholder="e.g. Management Plane Security">
                            </div>

                            <div class="flex space-x-3 pt-2">
                                <button type="submit" class="bg-green-600 hover:bg-green-700 text-white font-bold py-1.5 px-4 rounded shadow transition text-xs">
                                    Confirm & Save Mapping
                                </button>
                                <button type="button" onclick="rejectProposal()" class="bg-gray-500 hover:bg-gray-600 text-white font-bold py-1.5 px-4 rounded shadow transition text-xs">
                                    Reject
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Mapping rules table -->
                <div class="bg-white rounded-lg shadow-sm overflow-hidden mt-8 p-6">
                    <h3 class="font-semibold text-gray-800 text-lg border-b pb-3 mb-4">Learned Mappings Store</h3>
                    <table class="w-full border-collapse" id="mappings-table">
                        <thead>
                            <tr class="bg-gray-50 border-b border-gray-100 text-gray-500 text-xs font-semibold text-left uppercase">
                                <th class="p-4">Pattern</th>
                                <th class="p-4">Target Field</th>
                                <th class="p-4">Strategy</th>
                                <th class="p-4">Status</th>
                                <th class="p-4 text-center">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100 text-sm" id="mappings-list-container">
                            <!-- Async Load -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB: Frameworks -->
            <div id="tab-frameworks" class="tab-content">
                <div class="bg-white rounded-lg shadow-sm p-6 max-w-4xl mx-auto">
                    <h3 class="font-semibold text-gray-800 text-lg border-b pb-3 mb-6">Security Baseline Framework Rules</h3>
                    <div class="space-y-6" id="frameworks-specification-feed">
                        <div class="text-center text-gray-400">Loading framework documentation...</div>
                    </div>
                </div>
            </div>

            <!-- TAB: Reports -->
            <div id="tab-reports" class="tab-content">
                <div class="bg-white rounded-lg shadow-sm overflow-hidden">
                    <div class="p-6 border-b border-gray-100">
                        <h3 class="font-semibold text-gray-800 text-lg">Generated Compliance Deliverables</h3>
                    </div>
                    <table class="w-full border-collapse">
                        <thead>
                            <tr class="bg-gray-50 border-b border-gray-100 text-gray-500 text-xs font-semibold text-left uppercase">
                                <th class="p-4">Device</th>
                                <th class="p-4">Vendor</th>
                                <th class="p-4">Generated At</th>
                                <th class="p-4">JSON Result</th>
                                <th class="p-4">PDF Report</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100 text-sm" id="reports-list-container">
                            <tr class="text-gray-400 text-center"><td colspan="5" class="p-4">No reports generated. Ingest configurations first.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB: Settings -->
            <div id="tab-settings" class="tab-content">
                <div class="max-w-2xl mx-auto bg-white p-8 rounded-lg shadow-sm">
                    <h3 class="text-lg font-semibold text-gray-800 mb-6">AI Interpretation & Settings Configuration</h3>
                    
                    <form id="settings-form" class="space-y-6">
                        <!-- AI Provider -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">AI Engine Provider</label>
                            <select id="settings-provider" onchange="toggleApiKeyField()" class="w-full border border-gray-300 rounded-md p-2 shadow-sm focus:ring focus:ring-blue-200">
                                <option value="mock">Local/Mock Provider (Offline & Safe)</option>
                                <option value="gemini">Google Gemini API</option>
                                <option value="openai">OpenAI API</option>
                                <option value="anthropic">Anthropic Claude SDK</option>
                            </select>
                        </div>

                        <!-- API Key -->
                        <div id="api-key-group" class="hidden">
                            <label class="block text-sm font-medium text-gray-700 mb-2">Provider API Key</label>
                            <input type="password" id="settings-api-key" class="w-full border border-gray-300 rounded-md p-2 shadow-sm focus:ring focus:ring-blue-200" placeholder="Paste your API key here">
                        </div>

                        <!-- Model name -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Model Name</label>
                            <input type="text" id="settings-model" class="w-full border border-gray-300 rounded-md p-2 shadow-sm focus:ring focus:ring-blue-200" placeholder="e.g. gemini-1.5-flash or gpt-4o">
                        </div>

                        <!-- Allow Fallback -->
                        <div>
                            <label class="inline-flex items-center">
                                <input type="checkbox" id="settings-allow-llm" class="form-checkbox text-blue-600 rounded">
                                <span class="ml-2 text-sm text-gray-700">Allow AI Fallback for unrecognized configuration formats</span>
                            </label>
                        </div>

                        <!-- Min confidence -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Minimum Confidence Threshold (<span id="confidence-val">0.60</span>)</label>
                            <input type="range" id="settings-confidence" min="0.0" max="1.0" step="0.05" oninput="document.getElementById('confidence-val').innerText = parseFloat(this.value).toFixed(2)" class="w-full">
                            <p class="text-xs text-gray-400 mt-1">AI findings with confidence below this threshold will escalate to NEEDS_REVIEW.</p>
                        </div>

                        <div class="flex justify-end pt-4">
                            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded shadow transition">
                                Save Settings
                            </button>
                        </div>
                    </form>
                </div>
            </div>

        </main>
    </div>

    <!-- SPA JS Code -->
    <script>
        let fields = [];
        let allFindings = [];

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
            
            document.getElementById('tab-' + tabId).classList.add('active');
            const link = document.getElementById('link-' + tabId);
            if (link) link.classList.add('active');

            // Set Header Title
            const titleMap = {
                dashboard: 'Overview Dashboard',
                upload: 'Upload Configurations',
                devices: 'Device Inventory',
                findings: 'Global Findings',
                training: 'AI Training Center',
                frameworks: 'Compliance Frameworks',
                reports: 'Generated Reports',
                settings: 'System & API Settings'
            };
            document.getElementById('current-page-title').innerText = titleMap[tabId] || 'NetAudit';

            // Custom Page Init Loading
            if (tabId === 'dashboard') loadDashboardData();
            if (tabId === 'devices') loadDevices();
            if (tabId === 'findings') loadFindings();
            if (tabId === 'training') loadTrainingData();
            if (tabId === 'frameworks') loadFrameworksDoc();
            if (tabId === 'reports') loadReports();
            if (tabId === 'settings') loadSettings();
        }

        // Initialize fields dropdown & version
        async function init() {
            try {
                const verRes = await fetch('/api/version');
                const verData = await verRes.json();
                document.getElementById('core-version').innerText = verData.version;

                const res = await fetch('/api/fields');
                fields = await res.json();
                const select = document.getElementById('train-field');
                select.innerHTML = fields.map(f => `<option value="${f}">${f}</option>`).join('');

                loadDashboardData();
            } catch(e) {
                console.error("Initialization failed", e);
            }
        }

        async function loadDashboardData() {
            try {
                const res = await fetch('/api/dashboard');
                const stats = await res.json();
                
                document.getElementById('stat-total-devices').innerText = stats.total_devices;
                document.getElementById('stat-compliant').innerText = stats.compliant;
                document.getElementById('stat-non-compliant').innerText = stats.non_compliant;
                document.getElementById('stat-needs-review').innerText = stats.needs_review + stats.unknown_vendor;
                
                // Rollups
                const container = document.getElementById('framework-scores-container');
                if (Object.keys(stats.framework_rollup || {}).length === 0) {
                    container.innerHTML = `<p class="text-gray-400 text-sm">No compliance data recorded yet.</p>`;
                } else {
                    container.innerHTML = Object.entries(stats.framework_rollup).map(([fw, counts]) => {
                        const pass = counts.pass || 0;
                        const fail = counts.fail || 0;
                        const review = counts.needs_review || 0;
                        const total = pass + fail + review;
                        const score = total > 0 ? Math.round((pass / total) * 100) : 0;
                        return `
                            <div class="border-b border-gray-100 pb-3">
                                <div class="flex justify-between text-sm font-semibold text-gray-700">
                                    <span>${fw}</span>
                                    <span class="${score >= 80 ? 'text-green-600' : 'text-red-500'}">${score}% Score</span>
                                </div>
                                <div class="w-full bg-gray-200 rounded-full h-2 mt-2.5">
                                    <div class="bg-blue-600 h-2 rounded-full" style="width: ${score}%"></div>
                                </div>
                                <div class="flex justify-between text-[11px] text-gray-400 mt-1">
                                    <span>PASS: ${pass}</span>
                                    <span>FAIL: ${fail}</span>
                                    <span>REVIEW: ${review}</span>
                                </div>
                            </div>
                        `;
                    }).join('');
                }

                // AI Stats
                const metricsRes = await fetch('/api/metrics');
                const metrics = await metricsRes.json();
                document.getElementById('stat-approved-mappings').innerText = metrics.approved_mappings;
                document.getElementById('stat-unknown-patterns').innerText = metrics.unknown_patterns;
                document.getElementById('stat-avoided-calls').innerText = metrics.llm_calls_avoided;

                const setRes = await fetch('/api/settings');
                const settings = await setRes.json();
                document.getElementById('active-provider-badge').innerText = `Provider: ${settings.ai_provider}`;

            } catch(e) {
                console.error("Dashboard stats failed to load", e);
            }
        }

        // Upload Form Submit
        document.getElementById('upload-config-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const filesInput = document.getElementById('config-files');
            if (filesInput.files.length === 0) {
                alert("Please select at least one configuration file.");
                return;
            }

            const resultsFeed = document.getElementById('upload-results-feed');
            const resultsSection = document.getElementById('upload-scan-results');
            
            resultsSection.classList.remove('hidden');
            resultsFeed.innerHTML = '<div class="text-gray-500 text-sm"><i class="fa-solid fa-spinner animate-spin"></i> Processing configuration audit pipeline...</div>';

            const frameworks = Array.from(document.querySelectorAll('#upload-config-form input[type=checkbox]:checked')).map(el => el.value);

            for(let i=0; i < filesInput.files.length; i++) {
                const formData = new FormData();
                formData.append('config', filesInput.files[i]);
                formData.append('vendor', document.getElementById('upload-vendor').value);
                formData.append('frameworks', JSON.stringify(frameworks));

                try {
                    const res = await fetch('/api/upload', { method: 'POST', body: formData });
                    const result = await res.json();
                    
                    if (res.ok) {
                        const statusColor = result.status === 'audited' ? 'text-green-600' : 'text-red-500';
                        const summary = result.summary || { passed: 0, failed: 0, needs_review: 0 };
                        resultsFeed.innerHTML = `
                            <div class="p-4 bg-gray-50 rounded border border-gray-200 text-xs">
                                <div class="font-bold flex justify-between">
                                    <span>${result.source_file}</span>
                                    <span class="${statusColor}">${result.status.toUpperCase()}</span>
                                </div>
                                <div class="mt-2 grid grid-cols-3 gap-2 font-medium">
                                    <div class="text-green-600">PASS: ${summary.passed}</div>
                                    <div class="text-red-500">FAIL: ${summary.failed}</div>
                                    <div class="text-yellow-600">REVIEW: ${summary.needs_review}</div>
                                </div>
                                ${result.error ? `<div class="mt-2 text-red-600 font-mono">${result.error}</div>` : ''}
                            </div>
                        `;
                    } else {
                        resultsFeed.innerHTML = `<div class="text-red-500 text-xs font-mono">Upload Error: ${result.message}</div>`;
                    }
                } catch(err) {
                    resultsFeed.innerHTML = `<div class="text-red-500 text-xs font-mono">Network Error: ${err}</div>`;
                }
            }
            loadDashboardData();
        });

        // Track selected files
        document.getElementById('config-files').addEventListener('change', (e) => {
            const list = document.getElementById('selected-files-list');
            list.innerText = Array.from(e.target.files).map(f => f.name).join(', ');
        });

        // Load devices inventory
        async function loadDevices() {
            try {
                const res = await fetch('/api/devices');
                const list = await res.json();
                const tbody = document.getElementById('devices-list-container');
                
                if (list.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-400">No devices in inventory.</td></tr>`;
                    return;
                }

                tbody.innerHTML = list.map(dev => {
                    const statusClass = dev.status === 'audited' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800';
                    return `
                        <tr class="hover:bg-gray-50 border-b border-gray-100 transition">
                            <td class="p-4 font-bold text-gray-700">${dev.hostname}</td>
                            <td class="p-4 text-gray-500">${dev.vendor} (${dev.os_family})</td>
                            <td class="p-4 font-mono text-xs text-gray-400">${dev.serial_number || '-'}</td>
                            <td class="p-4"><span class="px-2.5 py-0.5 rounded-full text-xs font-medium ${statusClass}">${dev.status}</span></td>
                            <td class="p-4 text-xs text-gray-400">${new Date(dev.ingested_at).toLocaleString()}</td>
                            <td class="p-4 text-center">
                                <button onclick="showDeviceDetails('${dev.device_key}')" class="bg-blue-50 text-blue-600 hover:bg-blue-100 font-bold py-1 px-3 rounded text-xs transition">
                                    <i class="fa-solid fa-eye"></i> Details
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch(e) {
                console.error("Failed to load devices", e);
            }
        }

        // Show specific device details
        async function showDeviceDetails(deviceKey) {
            try {
                const pane = document.getElementById('device-details-pane');
                pane.classList.remove('hidden');
                pane.scrollIntoView({ behavior: 'smooth' });

                const res = await fetch(`/api/devices/${encodeURIComponent(deviceKey)}`);
                const device = await res.json();

                document.getElementById('details-device-title').innerText = device.hostname;
                document.getElementById('details-device-key').innerText = device.device_key;
                document.getElementById('details-vendor').innerText = device.vendor;
                document.getElementById('details-os').innerText = device.os_family;
                document.getElementById('details-serial').innerText = device.serial_number || 'null';
                document.getElementById('details-hash').innerText = device.source_hash || 'null';
                document.getElementById('details-source').innerText = device.source_file || '-';

                // Render baseline fields
                const baselineContainer = document.getElementById('details-baseline-fields');
                
                // Parse baseline from findings/observations
                // We will fetch the baseline fields dynamically from findings status or display them
                const baselineFieldsRes = await fetch(`/api/devices/${encodeURIComponent(deviceKey)}`);
                const baseData = await baselineFieldsRes.json();
                
                const observations = baseData.findings || [];
                baselineContainer.innerHTML = observations.map(f => {
                    const icon = f.status === 'PASS' ? 'fa-circle-check text-green-500' : (f.status === 'FAIL' ? 'fa-circle-xmark text-red-500' : 'fa-circle-exclamation text-yellow-500');
                    return `
                        <div class="p-3 hover:bg-gray-50 flex justify-between items-start">
                            <div>
                                <span class="font-bold block text-gray-700">${f.title}</span>
                                <span class="text-xs text-gray-400 font-mono">${f.control_id}</span>
                                <p class="text-[11px] text-gray-500 mt-1">${f.evidence}</p>
                            </div>
                            <span class="flex items-center space-x-1 font-bold text-xs"><i class="fa-solid ${icon}"></i> <span>${f.status}</span></span>
                        </div>
                    `;
                }).join('');

                // Render findings remediations
                const findingsContainer = document.getElementById('details-device-findings');
                const fails = observations.filter(f => f.status === 'FAIL' || f.status === 'NEEDS_REVIEW');
                if (fails.length === 0) {
                    findingsContainer.innerHTML = `<div class="p-4 bg-green-50 text-green-800 text-sm border border-green-100 rounded">Device is fully compliant with all framework controls. No remediation needed.</div>`;
                } else {
                    findingsContainer.innerHTML = fails.map(f => {
                        let cliRem = "";
                        if (f.remediation) {
                            try {
                                const remObj = JSON.parse(f.remediation);
                                if (remObj.cli && remObj.cli.length > 0) {
                                    cliRem = `
                                        <div class="mt-2">
                                            <span class="font-semibold text-gray-600 block text-[11px] uppercase">Remediation Script:</span>
                                            <pre class="bg-gray-900 text-green-400 p-3 rounded font-mono text-[11px] mt-1 overflow-x-auto">${remObj.cli.join('\\n')}</pre>
                                        </div>
                                    `;
                                }
                            } catch(err) {
                                // raw string
                            }
                        }
                        return `
                            <div class="p-4 border border-gray-200 rounded-lg bg-white shadow-sm space-y-2 text-xs">
                                <div class="flex justify-between border-b pb-2">
                                    <span class="font-bold text-gray-800">${f.title} (${f.control_id})</span>
                                    <span class="font-bold text-red-500">${f.status}</span>
                                </div>
                                <p class="text-gray-500"><span class="font-semibold">Evidence:</span> ${f.evidence}</p>
                                ${cliRem}
                            </div>
                        `;
                    }).join('');
                }

            } catch(e) {
                console.error("Device details failed to load", e);
            }
        }

        // Load global findings
        async function loadFindings() {
            try {
                const res = await fetch('/api/findings');
                allFindings = await res.json();
                applyFindingsFilter();
            } catch(e) {
                console.error("Failed to load findings", e);
            }
        }

        function applyFindingsFilter() {
            const statusFilter = document.getElementById('filter-findings-status').value;
            const severityFilter = document.getElementById('filter-findings-severity').value;
            const tbody = document.getElementById('findings-list-container');
            
            const filtered = allFindings.filter(f => {
                if (statusFilter !== 'ALL' && f.status !== statusFilter) return false;
                if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
                return true;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-400">No findings match the selected filter.</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map(f => {
                const verdictClass = f.status === 'PASS' ? 'text-green-600 font-bold' : (f.status === 'FAIL' ? 'text-red-500 font-bold' : 'text-yellow-600 font-bold');
                const severityClass = f.severity === 'high' ? 'bg-red-100 text-red-800' : (f.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' : 'bg-blue-100 text-blue-800');
                return `
                    <tr class="hover:bg-gray-50 border-b border-gray-100 transition text-xs">
                        <td class="p-4 font-bold text-gray-700">${f.hostname}</td>
                        <td class="p-4 text-gray-500 font-semibold">${f.framework}</td>
                        <td class="p-4"><strong>${f.title}</strong><br><span class="text-[10px] text-gray-400">${f.control_id}</span></td>
                        <td class="p-4 ${verdictClass}">${f.status}</td>
                        <td class="p-4"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${severityClass}">${f.severity}</span></td>
                        <td class="p-4 font-mono text-[10px] text-gray-500 max-w-xs truncate" title="${f.evidence}">${f.evidence}</td>
                    </tr>
                `;
            }).join('');
        }

        // Load training center unknown lines & mappings
        async function loadTrainingData() {
            try {
                // Mappings
                const mapRes = await fetch('/api/mappings');
                const mappings = await mapRes.json();
                const tbody = document.getElementById('mappings-list-container');
                
                if (mappings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-gray-400">No mapping rules defined.</td></tr>';
                } else {
                    tbody.innerHTML = mappings.map(m => `
                        <tr class="hover:bg-gray-50 border-b border-gray-100 transition text-xs" style="${m.status === 'deleted' ? 'display:none;' : ''}">
                            <td class="p-4 font-mono">${m.pattern}<br><small class="text-gray-400">${m.vendor}</small></td>
                            <td class="p-4 font-bold text-blue-600">${m.field}</td>
                            <td class="p-4 text-gray-400 font-medium">${m.extraction_strategy}</td>
                            <td class="p-4"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${m.status === 'approved' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}">${m.status}</span></td>
                            <td class="p-4 text-center">
                                <div class="flex justify-center space-x-2">
                                    ${m.status !== 'approved' ? `<button class="bg-green-50 text-green-600 hover:bg-green-100 py-1 px-2 rounded font-bold text-[10px]" onclick="approveMapping('${m.mapping_id}')">Approve</button>` : ''}
                                    ${m.status === 'approved' ? `<button class="bg-gray-100 text-gray-600 hover:bg-gray-200 py-1 px-2 rounded font-bold text-[10px]" onclick="disableMapping('${m.mapping_id}')">Disable</button>` : ''}
                                    <button class="bg-red-50 text-red-500 hover:bg-red-100 py-1 px-2 rounded font-bold text-[10px]" onclick="deleteMapping('${m.mapping_id}')">Delete</button>
                                </div>
                            </td>
                        </tr>
                    `).join('');
                }

                // Check active devices to extract some unknown lines for training simulation
                const devRes = await fetch('/api/devices');
                const devices = await devRes.json();
                const feed = document.getElementById('unknown-lines-feed');
                
                if (devices.length === 0) {
                    feed.innerHTML = `<div class="p-4 text-center text-gray-400">Ingest a configuration first.</div>`;
                    return;
                }

                // Query details of first device to extract unrecognized lines
                const firstDev = devices[0];
                const resDetails = await fetch(`/api/devices/${encodeURIComponent(firstDev.device_key)}`);
                const fullDev = await resDetails.json();
                
                // Get config text & simulate unrecognized lines if any, or pull unrecognized lines via API
                const configForm = new FormData();
                configForm.append('config', new Blob([fullDev.config_text || ""], { type: 'text/plain' }), 'config.conf');
                
                const parseRes = await fetch('/api/upload', { method: 'POST', body: configForm });
                const parseData = await parseRes.json();
                
                const unrecognized = parseData.unrecognized_lines || [];
                if (unrecognized.length === 0) {
                    feed.innerHTML = `<div class="p-4 text-center text-green-600 font-bold"><i class="fa-solid fa-circle-check"></i> No unrecognized lines! Entire configuration is understood.</div>`;
                } else {
                    feed.innerHTML = unrecognized.map(line => `
                        <div class="p-3 hover:bg-blue-50 cursor-pointer flex justify-between items-center transition" onclick="selectLineForTraining('${escapeHtml(line.text)}', '${parseData.vendor}', '${parseData.os_family}')">
                            <span>L${line.line_number}: ${escapeHtml(line.text)}</span>
                            <span class="text-blue-500 font-bold hover:underline">Train <i class="fa-solid fa-chevron-right"></i></span>
                        </div>
                    `).join('');
                }

            } catch(e) {
                console.error("Failed to load training center mappings", e);
            }
        }

        function escapeHtml(text) {
            return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }

        async function selectLineForTraining(lineText, vendor, os) {
            const formCard = document.getElementById('training-form-card');
            formCard.classList.remove('hidden');
            formCard.scrollIntoView({ behavior: 'smooth' });

            document.getElementById('train-raw-line').value = lineText;
            document.getElementById('train-mapping-id').value = 'LM-' + Math.floor(Math.random() * 100000);
            
            // Suggest pattern
            document.getElementById('train-pattern').value = lineText.split(' ').slice(0, 2).join(' ');

            // Fetch AI Mapping proposal
            const propBox = document.getElementById('proposal-box');
            const propContent = document.getElementById('proposal-content');
            propBox.classList.remove('hidden');
            propContent.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Requesting AI semantic mapping suggestion...';

            try {
                const res = await fetch('/api/propose', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ vendor, os_family: os, line: lineText })
                });
                const suggestion = await res.json();
                
                propContent.innerHTML = `
                    <div><strong>Security Concept:</strong> <span class="font-semibold text-blue-900">${suggestion.concept || suggestion.compliance_relevance || '-'}</span></div>
                    <div><strong>Normalized Field:</strong> <code class="bg-blue-100 p-0.5 rounded">${suggestion.field}</code></div>
                    <div><strong>Extracted Value:</strong> <code class="bg-blue-100 p-0.5 rounded">${suggestion.value || '-'}</code></div>
                    <div><strong>Confidence:</strong> <span class="font-bold text-blue-700">${Math.round((suggestion.confidence || 0) * 100)}%</span> <span class="text-xs text-gray-500">(${suggestion.source})</span></div>
                    <div class="mt-1"><strong>Reasoning:</strong> ${suggestion.reasoning}</div>
                `;

                document.getElementById('train-concept').value = suggestion.concept || suggestion.compliance_relevance || '';
                document.getElementById('train-field').value = suggestion.field || '';
                document.getElementById('train-value').value = suggestion.value || '';
                if (suggestion.pattern) document.getElementById('train-pattern').value = suggestion.pattern;
                document.getElementById('train-relevance').value = suggestion.compliance_relevance || suggestion.concept || 'General Security';
                if (suggestion.extraction_strategy) {
                    document.getElementById('train-strategy').value = suggestion.extraction_strategy;
                } else if (String(suggestion.value).toLowerCase() === 'true' || String(suggestion.value).toLowerCase() === 'false') {
                    document.getElementById('train-strategy').value = 'exact';
                } else {
                    document.getElementById('train-strategy').value = 'token';
                }
                if (suggestion.regex_pattern) {
                    document.getElementById('train-regex-pattern').value = suggestion.regex_pattern;
                }
                toggleRegexGroup();

            } catch(e) {
                propContent.innerText = "Could not reach suggestion provider. Please fill the mapping parameters manually.";
            }
        }

        document.getElementById('training-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const mapping = {
                mapping_id: document.getElementById('train-mapping-id').value,
                vendor: document.getElementById('active-provider-badge').innerText.split(': ')[1].toLowerCase(),
                os_family: 'unknown',
                pattern: document.getElementById('train-pattern').value,
                field: document.getElementById('train-field').value,
                extraction_strategy: document.getElementById('train-strategy').value,
                regex_pattern: document.getElementById('train-regex-pattern').value || null,
                compliance_control: document.getElementById('train-relevance').value,
                evidence_example: document.getElementById('train-raw-line').value,
                status: 'approved',
                approval_state: 'approved'
            };

            const res = await fetch('/api/mappings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(mapping)
            });

            if (res.ok) {
                alert("Mapping saved and approved!");
                document.getElementById('training-form-card').classList.add('hidden');
                loadTrainingData();
            } else {
                const err = await res.json();
                alert("Error: " + err.message);
            }
        });

        function toggleRegexGroup() {
            const val = document.getElementById('train-strategy').value;
            const group = document.getElementById('train-regex-group');
            if (val === 'regex') group.classList.remove('hidden');
            else group.classList.add('hidden');
        }

        async function approveMapping(id) {
            await fetch('/api/mappings/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mapping_id: id })
            });
            loadTrainingData();
        }

        async function disableMapping(id) {
            await fetch('/api/mappings/disable', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mapping_id: id })
            });
            loadTrainingData();
        }

        async function deleteMapping(id) {
            if (confirm("Delete this mapping rule?")) {
                await fetch('/api/mappings/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mapping_id: id })
                });
                loadTrainingData();
            }
        }

        function rejectProposal() {
            document.getElementById('training-form-card').classList.add('hidden');
        }

        // Load Settings
        async function loadSettings() {
            try {
                const res = await fetch('/api/settings');
                const settings = await res.json();
                
                document.getElementById('settings-provider').value = settings.ai_provider;
                document.getElementById('settings-api-key').value = settings.api_key;
                document.getElementById('settings-model').value = settings.llm_model;
                document.getElementById('settings-allow-llm').checked = settings.allow_llm;
                document.getElementById('settings-confidence').value = settings.min_confidence;
                document.getElementById('confidence-val').innerText = parseFloat(settings.min_confidence).toFixed(2);
                
                toggleApiKeyField();
            } catch(e) {
                console.error("Settings load failed", e);
            }
        }

        document.getElementById('settings-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const data = {
                ai_provider: document.getElementById('settings-provider').value,
                api_key: document.getElementById('settings-api-key').value,
                llm_model: document.getElementById('settings-model').value,
                allow_llm: document.getElementById('settings-allow-llm').checked,
                min_confidence: parseFloat(document.getElementById('settings-confidence').value)
            };

            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            if (res.ok) {
                alert("Settings saved successfully!");
                loadDashboardData();
            } else {
                alert("Failed to save settings.");
            }
        });

        function toggleApiKeyField() {
            const provider = document.getElementById('settings-provider').value;
            const group = document.getElementById('api-key-group');
            if (provider === 'mock') group.classList.add('hidden');
            else group.classList.remove('hidden');
        }

        // Load generated reports
        async function loadReports() {
            try {
                const res = await fetch('/api/reports');
                const list = await res.json();
                const tbody = document.getElementById('reports-list-container');
                
                if (list.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-gray-400">No reports generated yet.</td></tr>`;
                    return;
                }

                tbody.innerHTML = list.map(rep => {
                    return `
                        <tr class="hover:bg-gray-50 border-b border-gray-100 transition text-sm">
                            <td class="p-4 font-bold text-gray-700">${rep.hostname}</td>
                            <td class="p-4 text-gray-500 uppercase text-xs">${rep.vendor}</td>
                            <td class="p-4 text-xs text-gray-400">${new Date(rep.generated_at).toLocaleString()}</td>
                            <td class="p-4 text-xs">
                                <a href="/reports/${rep.hostname}.cis.json" target="_blank" class="text-blue-600 hover:underline font-semibold"><i class="fa-solid fa-file-code"></i> JSON Result</a>
                            </td>
                            <td class="p-4 text-xs">
                                <a href="/reports/${rep.hostname}.pdf" target="_blank" class="text-red-500 hover:underline font-semibold"><i class="fa-solid fa-file-pdf"></i> Download PDF</a>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch(e) {
                console.error("Failed to load reports", e);
            }
        }

        // Load frameworks specification doc
        async function loadFrameworksDoc() {
            try {
                const res = await fetch('/api/frameworks');
                const specs = await res.json();
                const feed = document.getElementById('frameworks-specification-feed');
                
                feed.innerHTML = Object.entries(specs).map(([fwName, controls]) => {
                    return `
                        <div class="border-b pb-6">
                            <h4 class="text-lg font-bold text-blue-700 uppercase mb-3">${fwName}</h4>
                            <div class="space-y-4">
                                ${Object.entries(controls).map(([cId, details]) => {
                                    return `
                                        <div class="p-3 bg-gray-50 rounded border border-gray-100 text-xs">
                                            <div class="flex justify-between font-bold text-gray-700">
                                                <span>${details.title}</span>
                                                <span class="text-gray-400">${cId}</span>
                                            </div>
                                            <p class="text-gray-500 mt-1 leading-relaxed">${details.description}</p>
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        </div>
                    `;
                }).join('');
            } catch(e) {
                console.error("Failed to load framework docs", e);
            }
        }

        function filterTable(tableId, value) {
            const table = document.getElementById(tableId);
            const tr = table.getElementsByTagName('tr');
            const cleanVal = value.toLowerCase().trim();
            for (let i = 1; i < tr.length; i++) {
                let show = false;
                const td = tr[i].getElementsByTagName('td');
                for (let j = 0; j < td.length; j++) {
                    if (td[j] && td[j].innerText.toLowerCase().indexOf(cleanVal) > -1) {
                        show = true;
                        break;
                    }
                }
                tr[i].style.display = show ? "" : "none";
            }
        }

        // Start SPA
        init();
    </script>
</body>
</html>
"""


class TrainingHTTPHandler(BaseHTTPRequestHandler):
    store_path = Path("training/learned_mappings.jsonl")
    stats_path = Path("training/stats.json")
    settings_path = Path("training/settings.json")
    db_path = Path("training/db.sqlite")
    llm_client: Optional[Any] = None

    def __init__(self, *args, **kwargs):
        self.store = LearnedMappingStore(self.store_path)
        self.settings = self.load_settings()
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        pass

    def load_settings(self) -> dict:
        if self.settings_path.is_file():
            try:
                return json.loads(self.settings_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "allow_llm": False,
            "ai_provider": "mock",
            "api_key": "",
            "llm_model": "gemini-1.5-flash",
            "min_confidence": 0.6
        }

    def save_settings(self, data: dict) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings_path.write_text(json.dumps(data), encoding="utf-8")
        self.settings = data

    def get_ai_client(self) -> Any:
        provider = self.settings.get("ai_provider", "mock")
        api_key = self.settings.get("api_key", "")
        model = self.settings.get("llm_model", "gemini-1.5-flash")
        
        if provider == "openai":
            return OpenAIProvider(api_key=api_key, model=model)
        elif provider == "gemini":
            return GeminiProvider(api_key=api_key, model=model)
        elif provider == "anthropic":
            return AnthropicClient(api_key=api_key, model=model)
        else:
            return MockProvider()

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path_clean = url.path.rstrip("/")
        
        if path_clean in ("", "/training"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
            return

        elif path_clean == "/api/version":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"version": __version__}).encode("utf-8"))
            return

        elif path_clean == "/api/fields":
            fields = SecurityBaselineModel.observable_fields()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(fields).encode("utf-8"))
            return

        elif path_clean == "/api/metrics":
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

        elif path_clean == "/api/mappings":
            mappings = self.store.list_mappings()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = [m.model_dump(mode="json") for m in mappings]
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        elif path_clean == "/api/settings":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.settings).encode("utf-8"))
            return

        elif path_clean == "/api/dashboard":
            stats = db.get_dashboard_stats(self.db_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(stats).encode("utf-8"))
            return

        elif path_clean == "/api/devices":
            devices = db.list_devices(self.db_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(devices).encode("utf-8"))
            return

        elif path_clean.startswith("/api/devices/"):
            device_key = urllib.parse.unquote(path_clean[len("/api/devices/"):])
            device = db.get_device(self.db_path, device_key)
            if not device:
                self.send_error(404, "Device Not Found")
                return
            findings = db.get_device_findings(self.db_path, device_key)
            device["findings"] = findings
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(device).encode("utf-8"))
            return

        elif path_clean == "/api/findings":
            findings = db.list_findings(self.db_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(findings).encode("utf-8"))
            return

        elif path_clean == "/api/reports":
            reports = db.list_reports(self.db_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(reports).encode("utf-8"))
            return

        elif path_clean == "/api/frameworks":
            # Read security controls and group
            controls_file = Path(__file__).resolve().parents[1] / "rules" / "security_controls.json"
            if controls_file.is_file():
                try:
                    data = json.loads(controls_file.read_text(encoding="utf-8"))
                except Exception:
                    data = {}
            else:
                data = {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"CIS Controls": data}).encode("utf-8"))
            return

        elif path_clean.startswith("/reports/"):
            filename = urllib.parse.unquote(path_clean[len("/reports/"):])
            filepath = Path("reports") / filename
            if not filepath.is_file():
                self.send_error(404, "Report File Not Found")
                return
            self.send_response(200)
            if filename.endswith(".pdf"):
                self.send_header("Content-Type", "application/pdf")
            elif filename.endswith(".json"):
                self.send_header("Content-Type", "application/json")
            else:
                self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(filepath.read_bytes())
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        if url.path == "/api/settings":
            try:
                data = json.loads(body.decode("utf-8"))
                self.save_settings(data)
                self.send_response(200)
                self.end_headers()
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"message": str(e)}).encode("utf-8"))
            return

        elif url.path == "/api/upload":
            content_str = body.decode("utf-8", errors="replace")
            # Parse multipart/form-data simple boundaries
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
                    if not line.strip() and len(config_lines) == 0:
                        continue
                    config_lines.append(line)
            
            config_text = "\n".join(config_lines).strip()
            if not config_text:
                config_text = content_str.strip()

            # Check for secrets redaction requirement in incoming
            config_text = redact_secrets(config_text)

            # Get target frameworks (defaults to CIS)
            frameworks = ["CIS"]
            # Extract form field `frameworks` if present
            if "name=\"frameworks\"" in content_str:
                match = re.search(r'name="frameworks"\s*\r?\n\r?\n([^\r\n]+)', content_str)
                if match:
                    try:
                        frameworks = json.loads(match.group(1))
                    except Exception:
                        pass

            # Detect parser
            forced_vendor = None
            if "name=\"vendor\"" in content_str:
                match = re.search(r'name="vendor"\s*\r?\n\r?\n([^\r\n]+)', content_str)
                if match:
                    forced_vendor = match.group(1).strip()
                    if not forced_vendor:
                        forced_vendor = None

            try:
                parser_cls, confidence = registry.detect(
                    config_text,
                    allow_fallback=self.settings.get("allow_llm", False)
                )
            except Exception:
                parser_cls = LLMParser
                confidence = 0.05

            if forced_vendor:
                parser_cls = registry.get(forced_vendor)
                confidence = 1.0

            # Instantiate and parse
            def parser_factory(cls):
                if cls is LLMParser:
                    return LLMParser(
                        client=self.get_ai_client(),
                        min_confidence=self.settings.get("min_confidence", 0.6),
                        trust_absence_claims=False
                    )
                if cls is HybridParser:
                    return HybridParser(
                        llm=LLMParser(
                            client=self.get_ai_client(),
                            min_confidence=self.settings.get("min_confidence", 0.6)
                        )
                    )
                return cls()

            try:
                parser = parser_factory(parser_cls)
                baseline = parse_config(
                    parser,
                    config_text,
                    source_file="uploaded_config.conf",
                    parser_cls=parser_cls,
                    confidence=confidence
                )
                
                # Run the compliance engine
                outcome = evaluate(baseline, frameworks)
                report = build_report(baseline, outcome)
                
                # Adapt report into DeviceRecord
                record = record_from_audit(report, config_text, Path("uploaded_config.conf"), baseline=baseline)
                
                # Write PDFs / JSONs
                reports_dir = Path("reports")
                reports_dir.mkdir(parents=True, exist_ok=True)
                pdf_filename = f"{record.identity.field_value('hostname') or 'device'}.pdf"
                pdf_path = reports_dir / pdf_filename
                write_device_pdf(record, pdf_path, version=__version__)
                
                json_filename = f"{record.identity.field_value('hostname') or 'device'}.{frameworks[0].lower()}.json"
                json_path = reports_dir / json_filename
                json_path.write_text(report.to_json(), encoding="utf-8")
                
                # Save into SQLite DB
                db.save_audit_result(
                    self.db_path,
                    record,
                    config_text,
                    pdf_path=f"/reports/{pdf_filename}",
                    json_path=f"/reports/{json_filename}"
                )

                unrecognized = get_unrecognized_lines(config_text, baseline)
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "audited",
                    "source_file": record.source_file,
                    "vendor": baseline.provenance.vendor,
                    "os_family": baseline.provenance.os_family,
                    "unrecognized_lines": unrecognized,
                    "summary": {
                        "passed": record.summary.passed,
                        "failed": record.summary.failed,
                        "needs_review": record.summary.needs_review
                    }
                }).encode("utf-8"))
                
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"message": f"Pipeline failure: {e}"}).encode("utf-8"))
            return

        elif url.path == "/api/propose":
            try:
                data = json.loads(body.decode("utf-8"))
                vendor = data.get("vendor", "unknown")
                os_family = data.get("os_family", "unknown")
                line = data.get("line", "")
            except Exception:
                self.send_response(400)
                self.end_headers()
                return

            client = self.get_ai_client() if self.settings.get("allow_llm") else None
            try:
                from .suggest import suggest_mapping
                sug = suggest_mapping(line=line, vendor=vendor, client=client)
                val_str = str(sug.extracted_value) if sug.extracted_value is not None else ""
                proposal = {
                    "field": sug.field,
                    "concept": sug.security_concept or sug.compliance_relevance,
                    "pattern": sug.pattern,
                    "extraction_strategy": sug.extraction_strategy,
                    "regex_pattern": sug.regex_pattern,
                    "value": val_str,
                    "confidence": sug.confidence,
                    "reasoning": sug.reasoning,
                    "compliance_relevance": sug.compliance_relevance or sug.security_concept,
                    "source": sug.source,
                    "alternatives": sug.alternatives,
                }
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
                self.store.approve_mapping(mid)
                self.send_response(200)
                self.end_headers()
            except Exception:
                self.send_response(400)
                self.end_headers()
            return

        elif url.path == "/api/mappings/disable":
            try:
                data = json.loads(body.decode("utf-8"))
                mid = data["mapping_id"]
                self.store.disable_mapping(mid)
                self.send_response(200)
                self.end_headers()
            except Exception:
                self.send_response(400)
                self.end_headers()
            return

        elif url.path == "/api/mappings/delete":
            try:
                data = json.loads(body.decode("utf-8"))
                mid = data["mapping_id"]
                self.store.delete_mapping(mid)
                self.send_response(200)
                self.end_headers()
            except Exception:
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
    print(f"NetAudit Engine & Dashboard running on http://localhost:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
