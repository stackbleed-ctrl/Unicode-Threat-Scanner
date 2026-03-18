#!/bin/bash
# publish.sh — build and upload unicode-threat-scanner to PyPI
#
# Prerequisites:
#   pip install build twine
#   Set TWINE_USERNAME / TWINE_PASSWORD, or use a ~/.pypirc token:
#     [pypi]
#     username = __token__
#     password = pypi-<your-api-token>
#
# Usage:
#   chmod +x publish.sh && ./publish.sh            # upload to PyPI
#   ./publish.sh --test                            # upload to TestPyPI first

set -euo pipefail

TARGET="pypi"
if [[ "${1:-}" == "--test" ]]; then
    TARGET="testpypi"
    echo ">> Targeting TestPyPI"
fi

echo ">> Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info

echo ">> Building sdist + wheel..."
python -m build

echo ">> Checking distributions..."
python -m twine check dist/*

if [[ "$TARGET" == "testpypi" ]]; then
    echo ">> Uploading to TestPyPI..."
    python -m twine upload --repository testpypi dist/*
    echo ""
    echo "Install from TestPyPI:"
    echo "  pip install --index-url https://test.pypi.org/simple/ unicode-threat-scanner"
else
    echo ">> Uploading to PyPI..."
    python -m twine upload dist/*
    echo ""
    echo "Install:"
    echo "  pip install unicode-threat-scanner"
fi
