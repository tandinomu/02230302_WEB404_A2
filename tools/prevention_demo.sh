#!/usr/bin/env bash
# prevention_demo.sh
# Runs the standalone vulnerable.php vs secure.php side by side, with a normal
# login and two classic auth-bypass payloads, so the fix is visible at a glance.
# Uses a throwaway Docker PHP container (nothing installed on the host).
#
# Usage:  bash tools/prevention_demo.sh
set -euo pipefail

IMG="php:8.3-cli"
DIR="$(cd "$(dirname "$0")/.." && pwd)/prevention"   # the prevention/ folder

# Run one PHP script inside a disposable container with prevention/ mounted.
run() { docker run --rm -v "$DIR:/app" -w /app "$IMG" php "$@"; }

echo "############ 1) NORMAL LOGIN (correct password) ############"
echo "--- vulnerable ---"; run vulnerable.php "admin" "s3cr3t"
echo;  echo "--- secure ---";     run secure.php     "admin" "s3cr3t"

echo; echo "############ 2) ATTACK  admin' --  (wrong password) ############"
echo "--- vulnerable (expect GRANTED = bypass) ---"; run vulnerable.php "admin' --" "wrongpass"
echo;  echo "--- secure (expect DENIED = fixed) ---";    run secure.php     "admin' --" "wrongpass"

echo; echo "############ 3) ATTACK  ' OR '1'='1' --  ############"
echo "--- vulnerable (expect GRANTED = bypass) ---"; run vulnerable.php "' OR '1'='1' --" "x"
echo;  echo "--- secure (expect DENIED = fixed) ---";    run secure.php     "' OR '1'='1' --" "x"
