#!/bin/bash
set -e

cd /home/runner/actions-runner
CONFIG_DIR="./config_data"

if [ -f ".runner" ] || [ -f "${CONFIG_DIR}/.runner" ]; then
    echo "Runner already configured, checking for local config..."
    if [ ! -f ".runner" ]; then
        cp "${CONFIG_DIR}/.runner" "${CONFIG_DIR}/.credentials" "${CONFIG_DIR}/.credentials_rsaparams" . 2>/dev/null || true
    fi
else
    echo "First time setup: Registering with GitHub..."
    ./config.sh \
        --url "${GITHUB_URL:?GITHUB_URL required}" \
        --token "${GITHUB_TOKEN:?GITHUB_TOKEN required}" \
        --name "${RUNNER_NAME:-$(hostname)}" \
        --work "_work" \
        --unattended \
        --replace

    mkdir -p "${CONFIG_DIR}"
    cp .runner .credentials .credentials_rsaparams "${CONFIG_DIR}/" 2>/dev/null || true
fi

echo "Starting runner..."
exec ./run.sh