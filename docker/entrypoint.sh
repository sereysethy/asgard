#!/bin/bash
set -e

COWRIE_USER_ID=${COWRIE_LOCAL_UID:-1000}
COWRIE_GROUP_ID=${COWRIE_LOCAL_GID:-1000}
DOCKER_GROUP_ID=${DOCKER_LOCAL_GID:-1000}

groupmod -o -g "$COWRIE_GROUP_ID" cowrie
usermod -o -u "$COWRIE_USER_ID" cowrie
groupmod -o -u "$DOCKER_GROUP_ID" docker
chown -R cowrie:cowrie /home/appuser

exec gosu appuser python3 /app/myscript.py "$@"