#!/usr/bin/env python3
"""Compatibility wrapper for the packaged guideline conversion CLI.

Prefer:
  uv run convert-security-guide convert

This wrapper remains available for direct script execution:
  uv run scripts/convert_security_guide.py convert
"""

from __future__ import annotations

from app.tools.convert_security_guide import main


if __name__ == "__main__":
    raise SystemExit(main())
