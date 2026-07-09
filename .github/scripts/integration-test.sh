#!/usr/bin/env bash
# Integration test: exercise the real external dependencies the Mule app
# calls (JSONPlaceholder) end-to-end, and validate response shape.
#
# Exit non-zero on any failure. Writes a summary report to
# integration-report.md.
set -uo pipefail

REPORT="integration-report.md"
BASE="https://jsonplaceholder.typicode.com"
FAILURES=0
TOTAL=0

pass() { echo "- ✅ $1" >>"$REPORT"; }
fail() { echo "- ❌ $1" >>"$REPORT"; FAILURES=$((FAILURES + 1)); }

check() {
  local name=$1 url=$2 jq_expr=$3 expected=$4
  TOTAL=$((TOTAL + 1))
  local body http_code actual
  body=$(curl -sS -o /tmp/body.json -w '%{http_code}' "$url") || {
    fail "$name — curl failed"; return
  }
  http_code=$body
  if [[ "$http_code" != "200" ]]; then
    fail "$name — HTTP $http_code"
    return
  fi
  actual=$(jq -r "$jq_expr" /tmp/body.json 2>/dev/null || echo "<jq-error>")
  if [[ "$actual" == "$expected" ]]; then
    pass "$name — $jq_expr == $expected"
  else
    fail "$name — expected '$expected', got '$actual'"
  fi
}

: >"$REPORT"
{
  echo "# Integration Test Report"
  echo ""
  echo "Target: $BASE"
  echo ""
  echo "## Results"
} >>"$REPORT"

check "GET /users/1 returns id 1"            "$BASE/users/1"              '.id'          "1"
check "GET /users/1 returns name Leanne Graham" "$BASE/users/1"          '.name'        "Leanne Graham"
check "GET /users/1 returns username Bret"   "$BASE/users/1"              '.username'    "Bret"
check "GET /posts?userId=1 returns 10 posts" "$BASE/posts?userId=1"       'length'       "10"
check "GET /posts?userId=1 first post userId is 1" "$BASE/posts?userId=1" '.[0].userId'  "1"

{
  echo ""
  echo "## Summary"
  echo ""
  echo "Total: $TOTAL"
  echo "Failures: $FAILURES"
  echo ""
  if [[ $FAILURES -eq 0 ]]; then
    echo "**Status: PASSED ✅**"
  else
    echo "**Status: FAILED ❌**"
  fi
} >>"$REPORT"

cat "$REPORT"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$REPORT" >>"$GITHUB_STEP_SUMMARY"
fi

exit $FAILURES
