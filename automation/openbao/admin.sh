#!/usr/bin/env bash
# OpenBao administration for gx's identity key (setup A). Run on the host, from anywhere.
#
#   admin.sh init              first time: initialise and unlock OpenBao, enable signing,
#                              write gx's sign-only token. Shows the unseal key and admin token ONCE.
#   admin.sh import FILE.p12   put the identity key into OpenBao and the public chain into certs/,
#                              then delete FILE. Copy FILE to /dev/shm (RAM) first.
#   admin.sh unseal            unlock OpenBao after a restart
#   admin.sh token             issue a new sign-only token for gx (the old one is revoked)
#   admin.sh status            locked or not, which key, which certificate
#
# Everything that touches the key runs in the openbao-admin container; gx never sees it.
# Details: automation/README.md, "Setup A: own certificate + OpenBao".
set -euo pipefail
cd "$(dirname "$0")/../.."

admin() { docker compose run --rm "$@"; }

start_openbao() {
    docker compose up -d openbao >/dev/null
}

case "${1:-}" in
    init|unseal|token|status)
        start_openbao
        admin openbao-admin "$1"
        ;;
    import)
        file=${2:?usage: admin.sh import FILE.p12}
        [[ -f $file ]] || { echo "no such file: $file" >&2; exit 1; }
        file=$(realpath "$file")
        if [[ $file != /dev/shm/* ]]; then
            echo "WARNING: $file is on disk. Next time copy the .p12 to /dev/shm (RAM) first." >&2
            echo "         It will be overwritten and deleted after a successful import." >&2
        fi
        start_openbao
        admin -v "$file:/in/identity.p12:ro" openbao-admin import
        # Only reached after a successful import: the key is in OpenBao now.
        if [[ $file == /dev/shm/* ]]; then rm -f "$file"; else shred -u "$file"; fi
        echo "Deleted $file. Keep the original .p12 only in your organisation's secure storage."
        ;;
    *)
        sed -n '4,11p' "$0"
        exit 2
        ;;
esac
