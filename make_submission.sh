#!/bin/bash
# ============================================================
# make_submission.sh
# ------------------------------------------------------------
# Assembles the CSC3106 mini-project submission package in the
# structure required by the spec:
#
#   mini-project-submission/
#     report.pdf
#     part1/
#       README.md
#       analysis.py
#       4_auth.log
#       output/           (generated tables + figures)
#     part2/
#       <technical response files>
#
# The dev repo stays flat (code at root, LaTeX under report/);
# this script only produces the packaged artefact under dist/.
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"
PKG="$DIST/mini-project-submission"

rm -rf "$DIST"
mkdir -p "$PKG/part1/output" "$PKG/part2"

# --- report.pdf (build fresh, top level) --------------------
( cd "$ROOT/report" && ./build.sh >/dev/null )
cp "$ROOT/report/main.pdf" "$PKG/report.pdf"

# --- part1: README + code + input + generated outputs -------
cp "$ROOT/part1/README.md" "$PKG/part1/README.md"
cp "$ROOT/analysis.py"     "$PKG/part1/analysis.py"
cp "$ROOT/4_auth.log"      "$PKG/part1/4_auth.log"
cp "$ROOT"/output/*.csv    "$PKG/part1/output/"
cp "$ROOT"/output/*.png    "$PKG/part1/output/"

# --- part2: technical response files (no README) -----------
cp -r "$ROOT/part2/." "$PKG/part2/"

# --- zip ----------------------------------------------------
( cd "$DIST" && zip -rq mini-project-submission.zip mini-project-submission )

echo "Built: $DIST/mini-project-submission.zip"
echo
( cd "$DIST" && find mini-project-submission -type f | sort )
