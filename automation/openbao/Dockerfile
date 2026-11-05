# Admin tool for gx's identity key: the OpenBao CLI plus openssl and jq.
# Used only through automation/openbao/admin.sh; the key is handled in this container's
# RAM-only /work and goes straight into OpenBao. The gx container never sees it.
FROM openbao/openbao:2.7.1
USER root
RUN apk add --no-cache openssl jq
COPY admin-task.sh /usr/local/bin/gx-openbao-admin
ENTRYPOINT ["/bin/sh", "/usr/local/bin/gx-openbao-admin"]
