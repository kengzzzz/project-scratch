#!/bin/sh
set -eu

# Decrypt into a new directory. Installing it into the stopped server is separate.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "${script_dir}/vaultwarden_backup.py" restore "$@"
