# OpenBao server holding gx's identity key (setup A, see automation/README.md).
# Single node; data in the openbao_data volume, encrypted by OpenBao and unlocked by the unseal key.

storage "raft" {
  path    = "/openbao/file"
  node_id = "gx"
}

# Plain HTTP on purpose: the server is reachable only on the internal compose network
# "vault" (no published port, no outside access), shared with gx and the admin tool.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr      = "http://openbao:8200"
cluster_addr  = "http://openbao:8201"
disable_mlock = true      # recommended with raft storage
ui            = false

# gx's sign-only token is periodic: 90 days, extended on every gx run.
max_lease_ttl = "2160h"
