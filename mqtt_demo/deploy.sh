#!/bin/bash
# Sync source + .env to the remote and rebuild the container.
#
# Two host paths are used:
#   REMOTE_DIR  — compose project (source code, .env, docker-compose.yml)
#                 Convention: /mnt/user/compose/samsung-bridge/
#   APPDATA_DIR — bind-mount source for /config inside the container
#                 (client cert + key live here).
#                 Convention: /mnt/user/appdata/samsung-bridge/
#
# The remote must already have the certs in $APPDATA_DIR. Run once
# before the first deploy:
#
#   source .env
#   ssh "$SSH_HOST" mkdir -p "$APPDATA_DIR"
#   scp certs/client_fullchain.pem certs/client.key \
#       "$SSH_HOST:$APPDATA_DIR/"
#
# Subsequent deploys (this script) ship source code + .env only; the
# certs in $APPDATA_DIR are preserved.
set -e

# This script lives in mqtt_demo/ but the build context is the repo
# root (mqtt_demo/docker-compose.yml uses `context: ..`, since the
# image needs the smartthings_local library package alongside
# mqtt_demo/). Run everything from the repo root so the tar allowlist
# and remote layout line up with that context.
cd "$(dirname "$0")/.."

if [ ! -f mqtt_demo/.env ]; then
    echo "Error: mqtt_demo/.env file not found. Copy mqtt_demo/.env.example to mqtt_demo/.env and configure it."
    exit 1
fi

# Pull only the keys deploy.sh actually needs, without sourcing .env.
# Sourcing would tokenize unquoted spaces in values (e.g.
# `APPLIANCE_1_NAME=Samsung Dryer`) as shell commands.
get_env() {
    grep -E "^${1}=" mqtt_demo/.env | head -1 | cut -d= -f2-
}
SSH_HOST=$(get_env SSH_HOST)
REMOTE_DIR=$(get_env REMOTE_DIR)
APPDATA_DIR=$(get_env APPDATA_DIR)

: "${SSH_HOST:?SSH_HOST not set in .env}"
: "${REMOTE_DIR:?REMOTE_DIR not set in .env}"
: "${APPDATA_DIR:?APPDATA_DIR not set in .env}"

echo "Deploying to ${SSH_HOST}:${REMOTE_DIR}…"
ssh "${SSH_HOST}" mkdir -p "${REMOTE_DIR}" "${APPDATA_DIR}"

# Source code — explicit allowlist instead of an excludelist. Anything
# else in the repo (research files, certs, logs, the .git dir) stays
# local. smartthings_local/ is the library package mqtt_demo/ imports
# from; it needs to land as REMOTE_DIR's sibling of mqtt_demo/ so the
# compose file's `context: ..` resolves the same way it does locally.
COPYFILE_DISABLE=1 tar cz \
    smartthings_local/ \
    mqtt_demo/ \
    README.md \
    .gitignore \
    .dockerignore \
  | ssh "${SSH_HOST}" "cd ${REMOTE_DIR} && tar xz && find . -name '._*' -delete"

# Ship .env separately and lock it down on the remote.
scp mqtt_demo/.env "${SSH_HOST}:${REMOTE_DIR}/mqtt_demo/.env"
ssh "${SSH_HOST}" "chmod 600 ${REMOTE_DIR}/mqtt_demo/.env"

# Verify certs are present on the remote — they have to be uploaded
# once before the first build.
if ! ssh "${SSH_HOST}" "test -s ${APPDATA_DIR}/client_fullchain.pem && test -s ${APPDATA_DIR}/client.key"; then
    echo
    echo "WARNING: ${APPDATA_DIR}/client_fullchain.pem and client.key not"
    echo "found on the remote. The container will start but fail to"
    echo "connect to the appliance until you upload them, e.g.:"
    echo "  ssh ${SSH_HOST} mkdir -p ${APPDATA_DIR}"
    echo "  scp certs/client_fullchain.pem certs/client.key ${SSH_HOST}:${APPDATA_DIR}/"
    echo
fi

echo "Rebuilding container…"
ssh "${SSH_HOST}" "cd ${REMOTE_DIR}/mqtt_demo && docker compose up -d --build"

echo "Done."
echo "Logs:  ssh ${SSH_HOST} 'cd ${REMOTE_DIR}/mqtt_demo && docker compose logs -f'"
