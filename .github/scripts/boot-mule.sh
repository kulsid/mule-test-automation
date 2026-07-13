#!/usr/bin/env bash
# Boot Mule Standalone locally on the GitHub Actions runner, deploy the
# packaged application, and wait for the HTTP listener to become ready.
#
# Uses the publicly hosted Mule Community Edition tarball — no Anypoint
# credentials required. The demo app's flows only use core + http +
# dataweave features that work on both CE 4.4 and EE 4.9, so this is a
# faithful smoke test of the packaged JAR.
#
# Env:
#   MULE_VERSION            default 4.4.0
#   MULE_HTTP_PORT          default 8081
#   MULE_APP_JAR            path to the -mule-application.jar to deploy
#                           (default: pick the single JAR under target/)
#   MULE_HOME_DIR           where Mule will be extracted (default: $PWD/mule)
#   MULE_READY_TIMEOUT_S    max seconds to wait for :8081/hello (default: 120)
set -euo pipefail

MULE_VERSION=${MULE_VERSION:-4.4.0}
MULE_HTTP_PORT=${MULE_HTTP_PORT:-8081}
MULE_HOME_DIR=${MULE_HOME_DIR:-"$PWD/mule"}
MULE_READY_TIMEOUT_S=${MULE_READY_TIMEOUT_S:-120}

if [[ -z "${MULE_APP_JAR:-}" ]]; then
  MULE_APP_JAR=$(ls target/*-mule-application.jar 2>/dev/null | head -n1 || true)
fi
if [[ -z "$MULE_APP_JAR" || ! -f "$MULE_APP_JAR" ]]; then
  echo "ERROR: could not locate a *-mule-application.jar to deploy" >&2
  echo "       set MULE_APP_JAR or run 'mvn package' first" >&2
  exit 1
fi

echo "→ Mule version : $MULE_VERSION (Community Edition)"
echo "→ App JAR      : $MULE_APP_JAR"
echo "→ Mule home    : $MULE_HOME_DIR"
echo "→ HTTP port    : $MULE_HTTP_PORT"

# --- Fetch the Mule Standalone tarball ---------------------------------- #
TARBALL_DIR="$PWD/.mule-dist"
mkdir -p "$TARBALL_DIR"
TARBALL="$TARBALL_DIR/mule-standalone-${MULE_VERSION}.tar.gz"

MULE_CE_URL="https://repository.mulesoft.org/nexus/content/repositories/releases/org/mule/distributions/mule-standalone/${MULE_VERSION}/mule-standalone-${MULE_VERSION}.tar.gz"

echo "→ Downloading $MULE_CE_URL"
curl -sSfL --retry 3 --retry-delay 2 "$MULE_CE_URL" -o "$TARBALL"

if [[ ! -s "$TARBALL" ]]; then
  echo "ERROR: downloaded tarball is empty: $TARBALL" >&2
  exit 1
fi

# --- Extract ------------------------------------------------------------- #
rm -rf "$MULE_HOME_DIR"
mkdir -p "$MULE_HOME_DIR"
tar -xzf "$TARBALL" -C "$MULE_HOME_DIR" --strip-components=1
echo "→ Extracted to $MULE_HOME_DIR"

# --- Deploy the application --------------------------------------------- #
cp "$MULE_APP_JAR" "$MULE_HOME_DIR/apps/"
echo "→ Copied app JAR into $MULE_HOME_DIR/apps/"

# --- Start Mule --------------------------------------------------------- #
# `bin/mule start` daemonises and writes its own pid file under logs/.
"$MULE_HOME_DIR/bin/mule" start
echo "→ Mule started; waiting up to ${MULE_READY_TIMEOUT_S}s for :${MULE_HTTP_PORT}/hello"

# --- Wait for readiness ------------------------------------------------- #
deadline=$(( SECONDS + MULE_READY_TIMEOUT_S ))
until curl -fsS "http://localhost:${MULE_HTTP_PORT}/hello" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "ERROR: Mule did not become ready on :${MULE_HTTP_PORT} within ${MULE_READY_TIMEOUT_S}s" >&2
    echo "--- last 100 lines of mule log ---" >&2
    tail -n 100 "$MULE_HOME_DIR"/logs/mule.log 2>/dev/null \
      || tail -n 100 "$MULE_HOME_DIR"/logs/*.log 2>/dev/null \
      || echo "(no logs found)" >&2
    exit 1
  fi
  sleep 2
done

echo "✅ Mule is ready on http://localhost:${MULE_HTTP_PORT}"
