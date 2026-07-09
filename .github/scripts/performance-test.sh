#!/usr/bin/env bash
# Performance test (demo mode): boot a tiny local HTTP mock that returns
# canned JSONPlaceholder-shaped responses, then run Apache Bench (ab)
# against it. No external network calls — protects the real
# jsonplaceholder.typicode.com from CI load and rate limits.
#
# Thresholds (override via env):
#   REQUESTS         default 100
#   CONCURRENCY      default 10
#   MAX_MEAN_MS      default 100    (local mock — lower ceiling)
#   MAX_P95_MS       default 200
#   MIN_SUCCESS_PCT  default 99
#   MOCK_PORT        default 18080
set -uo pipefail

REQUESTS=${REQUESTS:-100}
CONCURRENCY=${CONCURRENCY:-10}
MAX_MEAN_MS=${MAX_MEAN_MS:-100}
MAX_P95_MS=${MAX_P95_MS:-200}
MIN_SUCCESS_PCT=${MIN_SUCCESS_PCT:-99}
MOCK_PORT=${MOCK_PORT:-18080}

REPORT="performance-report.md"
MOCK_LOG=$(mktemp)

# --- Mock server ---------------------------------------------------------- #
python3 - "$MOCK_PORT" >"$MOCK_LOG" 2>&1 <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = {"id": 1, "name": "Leanne Graham", "username": "Bret",
        "email": "Sincere@april.biz"}
POSTS = [{"userId": 1, "id": i, "title": f"post {i}", "body": f"body {i}"}
         for i in range(1, 11)]

class H(BaseHTTPRequestHandler):
    def log_message(self, *_): pass  # silence stderr
    def do_GET(self):
        if self.path == "/users/1":
            body = json.dumps(USER).encode()
        elif self.path.startswith("/posts"):
            body = json.dumps(POSTS).encode()
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

port = int(sys.argv[1])
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
MOCK_PID=$!
# Silence bash's "Terminated" job-control message when the trap fires.
disown "$MOCK_PID" 2>/dev/null || true
trap 'kill "$MOCK_PID" >/dev/null 2>&1; wait "$MOCK_PID" 2>/dev/null; rm -f "$MOCK_LOG"' EXIT

# --- Wait for the mock to bind ------------------------------------------- #
# The mock forks in background; probes will fail for the first ~100ms while
# Python is still binding the socket. Suppress curl's own error output — we
# only care about the exit code.
printf 'Waiting for mock server on 127.0.0.1:%s ' "$MOCK_PORT"
for i in $(seq 1 50); do
  if curl -s -o /dev/null "http://127.0.0.1:$MOCK_PORT/users/1"; then
    printf 'ready (after %sms)\n\n' $((i * 100))
    break
  fi
  sleep 0.1
  if [[ $i -eq 50 ]]; then
    printf '\nERROR: mock server did not start on port %s\n' "$MOCK_PORT" >&2
    cat "$MOCK_LOG" >&2
    exit 1
  fi
done

TARGETS=(
  "http://127.0.0.1:$MOCK_PORT/users/1"
  "http://127.0.0.1:$MOCK_PORT/posts?userId=1"
)

# --- Markdown report (artifact + step summary) --------------------------- #
: >"$REPORT"
{
  echo "# Performance Test Report (Local Mock)"
  echo ""
  echo "Mock target: 127.0.0.1:$MOCK_PORT (in-process Python HTTP server)"
  echo ""
  echo "Requests: $REQUESTS · Concurrency: $CONCURRENCY"
  echo ""
  echo "Thresholds: mean ≤ ${MAX_MEAN_MS}ms · p95 ≤ ${MAX_P95_MS}ms · success ≥ ${MIN_SUCCESS_PCT}%"
  echo ""
  echo "| Endpoint | Requests | Failed | Mean (ms) | p95 (ms) | Throughput (req/s) | Result |"
  echo "| --- | ---: | ---: | ---: | ---: | ---: | :---: |"
} >>"$REPORT"

# --- Console header ------------------------------------------------------- #
divider="────────────────────────────────────────────────────────────────────────"
printf '%s\n' "$divider"
printf '  PERFORMANCE TEST (LOCAL MOCK)\n'
printf '%s\n' "$divider"
printf '  Mock target      : 127.0.0.1:%s\n' "$MOCK_PORT"
printf '  Load             : %s requests, concurrency %s\n' "$REQUESTS" "$CONCURRENCY"
printf '  Thresholds       : mean ≤ %sms · p95 ≤ %sms · success ≥ %s%%\n' \
  "$MAX_MEAN_MS" "$MAX_P95_MS" "$MIN_SUCCESS_PCT"
printf '%s\n\n' "$divider"

FAILURES=0

for url in "${TARGETS[@]}"; do
  out=$(ab -n "$REQUESTS" -c "$CONCURRENCY" -k -q "$url" 2>&1) || true

  completed=$(echo "$out"  | awk '/Complete requests:/  {print $3}')
  failed=$(echo "$out"     | awk '/Failed requests:/    {print $3}')
  non2xx=$(echo "$out"     | awk '/Non-2xx responses:/  {print $3}')
  mean_ms=$(echo "$out"    | awk '/Time per request:.*mean\)/ && !/across/ {print $4}')
  p95_ms=$(echo "$out"     | awk '/^ *95% */ {print $2}')
  rps=$(echo "$out"        | awk '/Requests per second:/ {print $4}')

  non2xx=${non2xx:-0}
  failed=${failed:-0}
  completed=${completed:-0}
  mean_ms=${mean_ms:-0}
  p95_ms=${p95_ms:-0}
  rps=${rps:-0}

  bad=$((failed + non2xx))
  if [[ "$completed" -gt 0 ]]; then
    success_pct=$(awk "BEGIN{printf \"%.2f\", (($completed - $bad) / $completed) * 100}")
  else
    success_pct="0.00"
  fi

  # Per-metric pass/fail for the console output.
  awk -v m="$mean_ms"     -v t="$MAX_MEAN_MS"     'BEGIN{exit !(m+0 <= t+0)}' && mean_mark="OK  " || mean_mark="FAIL"
  awk -v p="$p95_ms"      -v t="$MAX_P95_MS"      'BEGIN{exit !(p+0 <= t+0)}' && p95_mark="OK  "  || p95_mark="FAIL"
  awk -v s="$success_pct" -v t="$MIN_SUCCESS_PCT" 'BEGIN{exit !(s+0 >= t+0)}' && succ_mark="OK  " || succ_mark="FAIL"

  if [[ "$mean_mark $p95_mark $succ_mark" == "OK   OK   OK  " ]]; then
    result="PASS ✅"
  else
    result="FAIL ❌"
    FAILURES=$((FAILURES + 1))
  fi

  # Console: block per endpoint, aligned columns.
  printf '  Endpoint         : %s\n' "$url"
  printf '  ─────────────────────────────────────────────────────\n'
  printf '    Completed       : %-10s\n' "$completed"
  printf '    Failed          : %-10s\n' "$bad"
  printf '    Success rate    : %-10s  [%s]\n' "${success_pct}%" "$succ_mark"
  printf '    Mean latency    : %-10s  [%s]  (≤ %sms)\n' "${mean_ms}ms" "$mean_mark" "$MAX_MEAN_MS"
  printf '    p95 latency     : %-10s  [%s]  (≤ %sms)\n' "${p95_ms}ms" "$p95_mark" "$MAX_P95_MS"
  printf '    Throughput      : %-10s\n' "${rps} req/s"
  printf '    Result          : %s\n\n' "$result"

  echo "| \`$url\` | $completed | $bad | $mean_ms | $p95_ms | $rps | $result |" >>"$REPORT"
done

if [[ $FAILURES -eq 0 ]]; then
  overall="PASSED ✅"
else
  overall="FAILED ❌ ($FAILURES endpoint(s) missed threshold)"
fi

# Console footer.
printf '%s\n' "$divider"
printf '  OVERALL: %s\n' "$overall"
printf '%s\n' "$divider"

# Markdown footer.
{
  echo ""
  echo "## Summary"
  echo ""
  echo "**Status: $overall**"
} >>"$REPORT"

# Post to GitHub step summary if available.
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$REPORT" >>"$GITHUB_STEP_SUMMARY"
fi

exit $FAILURES
