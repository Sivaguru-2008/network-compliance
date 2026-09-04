
import sys
from pathlib import Path
BASE_DIR = Path.cwd()
sys.path.insert(0, str(BASE_DIR))

from auditor.adapters import adapter_registry
from auditor.engine import ComplianceEngine

print('All 34 registered adapters:')
for k in sorted(adapter_registry._adapters.keys()):
    adapter = adapter_registry.get(k)
    print(f'  {k:25} -> {adapter.__class__.__name__} (parser: {adapter.parser_class.__name__ if adapter.parser_class else None})')
