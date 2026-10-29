#!/usr/bin/env bash
# The lab investigation through the installed `casefile` CLI. Run from the repository root,
# with `casefile` on PATH, in a directory it may write lab.casefile and report.html to.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
case_file="lab.casefile"
rm -f "$case_file" "$case_file-wal" "$case_file-shm"

casefile --case "$case_file" init "CI lab" --analyst ci
casefile --case "$case_file" import "$repo/examples/lab/scan-before.xml"
casefile --case "$case_file" import "$repo/examples/lab/auth.log" --year 2026
casefile --case "$case_file" finding add "Brute force" --statement "Many failures then a success"
casefile --case "$case_file" link F1 auth --lines 3-27
casefile --case "$case_file" finding status F1 supported --reason ci
casefile --case "$case_file" report --format html --out report.html
casefile --case "$case_file" verify
