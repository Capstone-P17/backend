"""Change analysis-result visibility from the configured application DB.

Usage:
  uv run python -m src.app.tools.set_analysis_visibility <analysis_id> public
  uv run python -m src.app.tools.set_analysis_visibility <analysis_id> private
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Literal

from src.app.db.session import SessionLocal, init_db
from src.app.services.result_store import DatabaseAnalysisResultStore


Visibility = Literal["public", "private"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Set an analysis result to public or private by analysis_id.",
    )
    parser.add_argument("analysis_id", help="Analysis UUID returned by the analysis API")
    parser.add_argument(
        "visibility",
        choices=("public", "private"),
        help="public lets every authenticated user read the result; private restores owner-only access",
    )
    args = parser.parse_args(argv)

    init_db()
    store = DatabaseAnalysisResultStore(SessionLocal)
    updated = store.set_visibility(
        args.analysis_id,
        is_public=args.visibility == "public",
    )
    if updated is None:
        print(
            json.dumps(
                {
                    "ok": False,
                    "analysis_id": args.analysis_id,
                    "error": "analysis result not found",
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1

    print(json.dumps({"ok": True, **updated}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
