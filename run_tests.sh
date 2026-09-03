#!/bin/bash

set -eu

MINCOVERAGE=${MINCOVERAGE:-90}
BASEDIR=$(readlink -f "$(dirname "$0")")
cd "${BASEDIR}"

echo "=== black ==="
black --check --diff c65of tests

echo "=== pylint ==="
pylint c65of tests

echo "=== pytest ==="
pytest -n auto --cov=c65of --cov-report=term-missing --cov-report=xml \
    --cov-fail-under="${MINCOVERAGE}" tests
