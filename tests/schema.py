#!/usr/bin/env python3
"""Validate the checked-in structural schema and the shared cross-architecture fixture."""
import copy
import json
from pathlib import Path
import subprocess
import sys
try:
    import jsonschema
except ImportError:
    print('NOT RUN: install python3-jsonschema for the schema contract test')
    raise SystemExit(77)
root = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, str(root/'scripts/generate-schema.py'),'--check'], check=True)
schema = json.loads((root/'docs/schema/portable-snapshot-v1.schema.json').read_text())
jsonschema.Draft202012Validator.check_schema(schema)
validator = jsonschema.Draft202012Validator(schema)
fixture = json.loads((root/'tests/fixtures/portable-v1.json').read_text())
validator.validate(fixture)
for modify in [lambda x:x.update(schema_version=2),lambda x:x['snapshot'].update(starttime_ticks=42),
               lambda x:x['snapshot']['environment']['entries'][0].update(present=1),
               lambda x:x['snapshot']['network']['interfaces'].update(count=65),
               lambda x:x['snapshot']['environment']['entries'][0].update(value={'encoding':'hex','value':'00'})]:
    invalid = copy.deepcopy(fixture); modify(invalid)
    assert not validator.is_valid(invalid)
print('PASS: schema, fixture and invalid structural examples')
