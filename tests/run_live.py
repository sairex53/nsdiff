#!/usr/bin/env python3
"""Skip only when procfs is unavailable or mounted for a different PID namespace."""
import os
from pathlib import Path
import subprocess
import sys
try:
    proc_pid = int(Path('/proc/self/stat').read_bytes().split(b' ', 1)[0])
except (OSError, ValueError):
    print('SKIP: cannot inspect /proc/self/stat')
    sys.exit(77)
if proc_pid != os.getpid():
    print('SKIP: /proc is mounted for a different PID namespace; live tests require matching procfs')
    sys.exit(77)
sys.exit(subprocess.run(sys.argv[1:]).returncode)
