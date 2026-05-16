FROM dhi.io/uv:0.11.14-debian13@sha256:71503b118ffdec9332851d42c539e9bff3af5f65d2d6d3bfb3f4354689a7ceb6 AS uv

FROM dhi.io/python:3.14.5-debian13-dev@sha256:6fb2fbaf1cbfedeac9b035bdc5538b237385164803254c8d47d784fc7395fe94 AS builder
ARG TARGETPLATFORM
COPY --from=uv /usr/local/bin/uv /usr/local/bin/
WORKDIR /app

RUN python -m venv /app/.venv
# GoReleaser dockers_v2 provides the built wheel under $TARGETPLATFORM/.
COPY ${TARGETPLATFORM}/*.whl /tmp/
RUN uv pip install --python /app/.venv/bin/python /tmp/*.whl

FROM dhi.io/python:3.14.5-debian13-dev@sha256:6fb2fbaf1cbfedeac9b035bdc5538b237385164803254c8d47d784fc7395fe94
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
