#!/bin/bash
# Smoke-check a security review report generated against tests/fixtures/vuln-app.
#
# Usage: ./tests/score-report.sh security-reviews/security-review-<stamp>.md
#
# Checks:
#   1. No planted secret literal appears verbatim (redaction rule) - hard fail
#   2. Keyword coverage of expected findings (crude heuristic - manual review
#      against tests/EXPECTED-FINDINGS.md is still required)
#
# Exit codes: 0 = pass, 1 = secret leak, 2 = coverage below threshold, 3 = usage
#
# NOTE: written for bash 3.2 (macOS default) - no associative arrays.

set -u
REPORT="${1:-}"
THRESHOLD=75

if [ -z "$REPORT" ] || [ ! -f "$REPORT" ]; then
  echo "Usage: $0 <path-to-report.md>"
  exit 3
fi

echo "Scoring $REPORT"
echo ""

# --- Check 1: redaction (hard fail) ---
SECRETS="
j8s3cr3t-d0-not-c0mm1t-4f2b9c
sk-proj-51f4k3k3y9x2q7
sk_live_51H4fakeN0tRe4l9x2q
p0stgres-sup3rpass
"
leaked=0
for s in $SECRETS; do
  if grep -qF "$s" "$REPORT"; then
    echo "FAIL  REDACTION  report contains planted secret: $s"
    leaked=1
  fi
done
if [ "$leaked" -eq 1 ]; then
  echo ""
  echo "RESULT: FAIL - secret literal(s) leaked into the report"
  exit 1
fi
echo "PASS  redaction: no planted secrets appear verbatim"
echo ""

# --- Check 2: keyword coverage (heuristic) ---
# VF ID <TAB> extended regex (case-insensitive). Any single match counts.
matched=0
total=0
while IFS="$(printf '\t')" read -r id pattern; do
  [ -z "$id" ] && continue
  total=$((total + 1))
  if grep -Eqi -- "$pattern" "$REPORT"; then
    matched=$((matched + 1))
  else
    echo "MISS  $id  (pattern: $pattern)"
  fi
done <<'EOF'
VF-01	ORDER BY|sort
VF-02	ping
VF-03	unserialize|node-serialize|deserializ
VF-04	no auth|without auth|unauthenticated|missing.*middleware
VF-05	IDOR|users/:id|object referen
VF-06	mass assignment|role
VF-07	SSRF|preview
VF-08	md5
VF-09	Math\.random
VF-10	algorithm
VF-11	JWT_SECRET|hardcoded (secret|key)|signing secret
VF-12	innerHTML|stored XSS
VF-13	upload|avatar|multer
VF-14	traversal|downloads|sendFile
VF-15	GraphQL|graphiql|BOLA|resolver
VF-16	prompt injection
VF-17	fetch_page|send_email|agent
VF-18	OpenAI|api key|sk-proj
VF-19	\.env
VF-20	Dockerfile|runs as root|docker
VF-21	0\.0\.0\.0|security group|terraform
VF-22	CSRF
VF-23	SameSite|httpOnly|cookie flag
VF-24	enumerat
VF-25	log.*(password|credential)|password.*log
VF-26	CORS
VF-27	open redirect|redirect
VF-28	reflected|welcome
VF-29	localStorage
VF-30	postMessage|origin
VF-31	race|coupon
VF-32	negative|client.supplied|total
VF-33	stack|verbose
VF-34	DEBUG
VF-35	compose|POSTGRES_PASSWORD|5432
VF-36	moment|EOL|end.of.life|unmaintained
EOF

coverage=$((matched * 100 / total))
echo ""
echo "Coverage: $matched/$total (${coverage}%), threshold ${THRESHOLD}%"
echo "NOTE: keyword matches are heuristic - confirm against tests/EXPECTED-FINDINGS.md,"
echo "including severity bands, control cases (no false positives), and redaction quality."

if [ "$coverage" -lt "$THRESHOLD" ]; then
  echo "RESULT: FAIL - coverage below threshold"
  exit 2
fi
echo "RESULT: PASS (smoke check)"
exit 0
