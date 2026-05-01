FROM dhi.io/uv:0.11.8-debian13@sha256:5aa09d752754ac43a0893266fefda5921e089ae5f78b9fe577805e5bdd9b8a4b AS uv

FROM dhi.io/python:3.14.4-debian13-dev@sha256:eec5f7badfdcb6685d36f1316d543bf54be5f202511883cae8215f13600fb317 AS builder
ARG TARGETPLATFORM
COPY --from=uv /usr/local/bin/uv /usr/local/bin/
WORKDIR /app

RUN python -m venv /app/.venv
# GoReleaser dockers_v2 provides the built wheel under $TARGETPLATFORM/.
COPY ${TARGETPLATFORM}/*.whl /tmp/
RUN uv pip install --python /app/.venv/bin/python /tmp/*.whl

FROM dhi.io/python:3.14.4-debian13-dev@sha256:eec5f7badfdcb6685d36f1316d543bf54be5f202511883cae8215f13600fb317
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"
RUN grep -q '^adm:' /etc/group || printf 'adm:x:4:\n' >> /etc/group \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9-dnsutils \
        ca-certificates \
        krb5-user \
        ldap-utils \
        libsasl2-modules-gssapi-mit \
        samba-common-bin \
        smbclient \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY --from=builder /app/.venv /app/.venv
ENTRYPOINT ["sambatui"]
