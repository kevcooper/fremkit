#!/bin/sh


START_DIR="${HOME}"


echo "==== Checking possibly related files ===="
find "${START_DIR}" \
    -type f \
    \( \
        -name cloud.json \
        -o -name contents.json \
        -o -name environment.json \
        -o -name truffleSecrets.json \
        -o -name secrets.json \
        -o -name npm.json \
        -o -name trufflehog-findings.json \
        -o -name setup_bun.js \
        -o -name bun_environment.js \
        -o -path '*/.github/workflows/discussion.yaml' \
    \) \
    2>/dev/null


echo "==== Checking for bun preinstall script ===="
find "${START_DIR}" \
    -type f \
    -name package.json \
    -exec grep -q setup_bun.js {} \; \
    -print \
    2>/dev/null


echo "==== Checking for bun binary ===="
stat ~/.bun/bin/bun" 2>/dev/null
