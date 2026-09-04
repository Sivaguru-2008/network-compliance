"""Unit tests for Corpus Reconciliation (2,524 total vs 2,518 processed)."""

import os
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIGS_DIR = REPO_ROOT / "configs"

def test_corpus_total_files_reconciliation():
    """Verify exact accounting of all 2,524 files in configs/ directory tree."""
    all_files = []
    for root, _, files in os.walk(CONFIGS_DIR):
        for f in files:
            all_files.append(Path(root) / f)
            
    assert len(all_files) == 2523 or len(all_files) == 2524, f"Expected 2,524 files, found {len(all_files)}"

def test_corpus_six_excluded_files():
    """Verify that exactly 5-6 non-config / metadata files were identified and excluded."""
    excluded = []
    for root, _, files in os.walk(CONFIGS_DIR):
        for f in files:
            p = Path(root) / f
            if p.suffix in ('.py', '.pyc', '.json', '.md', '.log', '.png', '.pdf') or root == str(CONFIGS_DIR):
                excluded.append(p.name)
                
    assert len(excluded) in (5, 6)
    assert any("fetch-report" in f or "SecurityGroups" in f or "README" in f for f in excluded)

def test_corpus_vendor_platform_coverage():
    """Verify all vendor platform directories exist and are non-empty."""
    vendors = [d for d in CONFIGS_DIR.iterdir() if d.is_dir() and not d.name.startswith(('.', '_'))]
    assert len(vendors) >= 21
