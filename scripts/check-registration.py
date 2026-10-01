#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
build = sys.argv[1] if len(sys.argv)>1 else 'build'
tests = json.loads(subprocess.check_output(['meson','introspect','--tests',build]))
commands = {Path(str(a)).name for t in tests for a in t['cmd']}
expected = {p.name for p in (root/'tests').glob('*.sh')} | {'portable.py','schema.py','test-sha256','test-unit'}
missing = expected-commands
if missing: raise SystemExit('Unregistered tests: '+', '.join(sorted(missing)))
print(f'All {len(expected)} test entry points registered ({len(tests)} Meson tests)')
