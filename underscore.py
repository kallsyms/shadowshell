#!/usr/bin/env python3
import os
import sys

from config import TMP_DIR

sid = os.getsid(0)
fn = os.path.join(TMP_DIR, f"{sid}-0")

if not os.path.exists(fn):
    sys.exit(0)

with open(fn, 'rb') as f:
    sys.stdout.buffer.write(f.read())
