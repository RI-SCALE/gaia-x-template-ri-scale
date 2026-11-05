#!/bin/sh
# Runs inside the openbao-admin container; started by automation/openbao/admin.sh on the host.
#
#   init     initialise OpenBao, show the unseal key and admin token once, unlock it,
#            enable signing and write gx's sign-only token to /secrets
#   unseal   unlock OpenBao after a restart
#   import   put the key from /in/identity.p12 into OpenBao (never exportable) and
#            write the public certificate chain to /certs
#   token    issue a new sign-only token for gx and revoke the old one
#   status   locked or not, which key, which certificate
#
# Secrets are typed at prompts, kept in shell variables or in /work (RAM only), and
# never written anywhere else. The admin token and unseal key are never stored.
set -eu

KEY_NAME=${GX_OPENBAO_KEY:-gx-identity}
POLICY=gx-sign
TOKEN_PERIOD=2160h                      # 90 days, extended by every gx run
TOKEN_FILE=/secrets/openbao-token       # mounted read-only into gx at /run/secrets/gx
CHAIN_FILE=/certs/identity-chain.pem    # public; read by gx's cert step
P12=/in/identity.p12
WORK=/work                              # tmpfs, mode 0700

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Prompt without echo; works on a terminal and with piped input (tests).
ask_secret() {
    printf '%s' "$1" >&2
    stty -echo 2>/dev/null || true
    IFS= read -r answer || true
    stty echo 2>/dev/null || true
    printf '\n' >&2
    printf '%s' "$answer"
}

# 0 = unsealed, 2 = sealed (bao status exit codes)
seal_state() { bao status >/dev/null 2>&1 && echo 0 || echo $?; }

wait_ready() {
    i=0
    while [ "$(seal_state)" = 1 ]; do
        i=$((i + 1)); [ "$i" -ge 30 ] && die "OpenBao at $BAO_ADDR does not answer"
        sleep 1
    done
}

require_unsealed() {
    [ "$(seal_state)" = 0 ] || die "OpenBao is sealed: run 'automation/openbao/admin.sh unseal' first"
}

admin_login() {
    BAO_TOKEN=$(ask_secret "OpenBao admin token: ")
    export BAO_TOKEN
    bao token lookup >/dev/null 2>&1 || die "this admin token is not valid"
}

unseal_with() {
    printf '%s' "$1" | bao write -format=json sys/unseal key=- | jq -e '.data.sealed == false' >/dev/null \
        || die "OpenBao is still sealed: wrong unseal key?"
}

write_gx_token() {
    new=$(bao token create -policy="$POLICY" -period="$TOKEN_PERIOD" -orphan -display-name=gx -field=token)
    if [ -s "$TOKEN_FILE" ]; then
        bao token revoke "$(cat "$TOKEN_FILE")" >/dev/null 2>&1 || true
    fi
    umask 077
    printf '%s' "$new" > "$TOKEN_FILE.new"
    mv "$TOKEN_FILE.new" "$TOKEN_FILE"
    echo "gx's sign-only token written to secrets/openbao-token (valid ${TOKEN_PERIOD}, extended on every gx run)"
}

setup_signing() {
    bao secrets list -format=json | jq -e 'has("transit/")' >/dev/null || bao secrets enable transit >/dev/null
    bao policy write "$POLICY" - >/dev/null <<EOF
# gx may read the public part of its key and sign with it. Nothing else: no export,
# no import, no delete, no other keys.
path "transit/keys/$KEY_NAME" { capabilities = ["read"] }
path "transit/sign/$KEY_NAME/*" { capabilities = ["update"] }
EOF
    echo "Signing enabled; policy '$POLICY' allows signing with key '$KEY_NAME' only"
    write_gx_token
}

cmd_init() {
    wait_ready
    bao status -format=json | jq -e '.initialized' >/dev/null && die "OpenBao is already initialised"
    out=$(bao operator init -key-shares=1 -key-threshold=1 -format=json)
    unseal_key=$(printf '%s' "$out" | jq -r '.unseal_keys_b64[0]')
    BAO_TOKEN=$(printf '%s' "$out" | jq -r '.root_token')
    export BAO_TOKEN
    cat >&2 <<EOF

=====================================================================
  Save these two values NOW, in your password manager - NOT on this
  host. They are shown only this once and are not stored anywhere.

    Unseal key  : $unseal_key
    Admin token : $BAO_TOKEN

  Unseal key : needed after every restart of OpenBao (admin.sh unseal)
  Admin token: needed for admin.sh import / token
=====================================================================
EOF
    printf 'Press Enter once both are saved... ' >&2
    read -r _ || true
    unseal_with "$unseal_key"
    echo "OpenBao unlocked"
    setup_signing
    echo "Next: admin.sh import /dev/shm/<file>.p12"
}

cmd_unseal() {
    wait_ready
    [ "$(seal_state)" = 0 ] && { echo "OpenBao is already unlocked"; return; }
    unseal_with "$(ask_secret "Unseal key: ")"
    echo "OpenBao unlocked"
}

key_type() {   # transit key type of the PEM private key in $1
    text=$(openssl pkey -in "$1" -noout -text 2>/dev/null)
    bits=$(printf '%s\n' "$text" | sed -n 's/.*Private-Key: (\([0-9]*\) bit.*/\1/p' | head -1)
    case "$text" in
        *modulus:*) case "$bits" in 2048|3072|4096) echo "rsa-$bits"; return;; esac ;;
        *"ASN1 OID: prime256v1"*) echo ecdsa-p256; return ;;
        *"ASN1 OID: secp384r1"*) echo ecdsa-p384; return ;;
        *"ASN1 OID: secp521r1"*) echo ecdsa-p521; return ;;
    esac
    return 1
}

covers_domain() {   # does the certificate in $1 name $GX_DOMAIN (exactly or by wildcard)?
    sans=$(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS://p')
    parent=${GX_DOMAIN#*.}
    printf '%s\n' "$sans" | grep -qxF -e "$GX_DOMAIN" -e "*.$parent"
}

certs_only() { awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$1"; }

cmd_import() {
    [ -f "$P12" ] || die "no .p12 file mounted at $P12 (use: admin.sh import FILE.p12)"
    wait_ready
    require_unsealed
    admin_login
    P12_PASS=$(ask_secret "Password of the .p12 file: ")
    export P12_PASS
    umask 077
    cd "$WORK"
    trap 'rm -f "$WORK"/*' EXIT

    # Newer openssl rejects the old encryption some CAs still use; retry with -legacy.
    p12() { openssl pkcs12 -in "$P12" -passin env:P12_PASS "$@" 2>/dev/null \
            || openssl pkcs12 -legacy -in "$P12" -passin env:P12_PASS "$@" 2>/dev/null; }
    p12 -nocerts -nodes > key.pem || die "cannot open the .p12 (wrong password?)"
    p12 -nokeys -clcerts > leaf.pem || die "cannot read the certificate from the .p12"
    p12 -nokeys -cacerts > ca.pem || true
    unset P12_PASS
    grep -q 'PRIVATE KEY' key.pem || die "the .p12 contains no private key"
    grep -q 'BEGIN CERTIFICATE' leaf.pem || die "the .p12 contains no certificate"

    [ "$(openssl pkey -in key.pem -pubout)" = "$(openssl x509 -in leaf.pem -noout -pubkey)" ] \
        || die "the private key does not belong to the certificate in the .p12"
    openssl x509 -in leaf.pem -noout -checkend 0 >/dev/null || die "the certificate has expired"
    if [ -n "${GX_DOMAIN:-}" ]; then
        covers_domain leaf.pem || die "the certificate is not issued for $GX_DOMAIN (GX_DOMAIN in .env)"
    fi
    type=$(key_type key.pem) || die "unsupported key type (need RSA 2048/3072/4096 or EC P-256/384/521)"

    # OpenBao takes the key as base64 PKCS#8 DER and wraps it for transport itself.
    openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER | base64 -w0 > key.b64
    rm -f key.pem
    if bao read transit/keys/"$KEY_NAME" >/dev/null 2>&1; then
        bao transit import-version transit/keys/"$KEY_NAME" @key.b64 >/dev/null 2>&1 \
            || die "OpenBao refused the key as a new version of '$KEY_NAME'"
        what="added as a new version of"
    else
        bao transit import transit/keys/"$KEY_NAME" @key.b64 type="$type" exportable=false >/dev/null 2>&1 \
            || die "OpenBao refused the key"
        what="imported as"
    fi
    rm -f key.b64

    { certs_only leaf.pem; certs_only ca.pem; } > "$CHAIN_FILE.new"
    chmod 644 "$CHAIN_FILE.new"
    mv "$CHAIN_FILE.new" "$CHAIN_FILE"
    version=$(bao read -format=json transit/keys/"$KEY_NAME" | jq -r '.data.latest_version')
    echo "Key ($type) $what '$KEY_NAME' (version $version), not exportable"
    echo "Certificate: $(openssl x509 -in leaf.pem -noout -subject -enddate | tr '\n' ' ')"
    echo "Public chain written to certs/identity-chain.pem"
}

cmd_token() {
    wait_ready
    require_unsealed
    admin_login
    write_gx_token
}

cmd_status() {
    wait_ready
    case "$(seal_state)" in
        0) echo "OpenBao: unlocked" ;;
        2) echo "OpenBao: SEALED - run 'admin.sh unseal'"; return ;;
    esac
    if [ -s "$TOKEN_FILE" ]; then
        BAO_TOKEN=$(cat "$TOKEN_FILE"); export BAO_TOKEN
        if info=$(bao read -format=json transit/keys/"$KEY_NAME" 2>/dev/null); then
            printf '%s' "$info" | jq -r '"Key \(.data.name): \(.data.type), version \(.data.latest_version), exportable: \(.data.exportable)"'
        else
            echo "Key $KEY_NAME: not readable with gx's token (not imported yet, or token expired)"
        fi
        if days=$(bao token lookup -format=json 2>/dev/null | jq -er '.data.ttl / 86400 | floor'); then
            echo "gx token: valid for $days more days"
        else
            echo "gx token: NOT VALID (expired or revoked) - run 'admin.sh token'"
        fi
    else
        echo "gx token: none (run 'admin.sh init' or 'admin.sh token')"
    fi
    if [ -s "$CHAIN_FILE" ]; then
        echo "Certificate: $(openssl x509 -in "$CHAIN_FILE" -noout -subject -enddate | tr '\n' ' ')"
    else
        echo "Certificate: none (run 'admin.sh import')"
    fi
}

case "${1:-}" in
    init|unseal|import|token|status) "cmd_$1" ;;
    *) sed -n '4,10p' "$0"; exit 2 ;;
esac
