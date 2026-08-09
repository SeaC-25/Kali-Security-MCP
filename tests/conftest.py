#!/usr/bin/env python3
"""Ensure repo root is on sys.path for tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
root_s = str(ROOT)
if root_s not in sys.path:
    sys.path.insert(0, root_s)
