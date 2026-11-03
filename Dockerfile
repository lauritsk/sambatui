# syntax=docker/dockerfile:1
ARG UV_IMAGE=dhi.io/uv:0.13.7-debian13-dev@sha256:2585792a493eef2a76aa2910cdf62a99c3c8e9a60aabb95724357d9bfe3f3b90
FROM ${UV_IMAGE} AS base
USER root
WORKDIR /app
ENV HOME=/home/app \
    KRB5CCNAME=FILE:/config/krb5cc \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
# Samba's post-install script expects Debian's adm group (absent in DHI).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends passwd \
    && groupadd --system adm \
    && apt-get install -y --no-install-recommends \
        bind9-dnsutils \
        ca-certificates \
        krb5-user \
        libgssapi-krb5-2 \
        ncurses-base \
        python3-samba \
        samba-common-bin \
    && useradd --create-home --uid 1000 app \
    && install -d -o app -g app -m 0700 /config \
    && samba-tool dns --help >/dev/null

FROM base AS dev
# uv's Python stays separate from Debian's Samba interpreter.
ENV UV_CACHE_DIR=/root/.cache/uv \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_PREFERENCE=only-managed
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libkrb5-dev
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi \
    && uv sync --frozen --no-editable

FROM dev AS test
ENV COVERAGE_FILE=/tmp/.coverage \
    HYPOTHESIS_STORAGE_DIRECTORY=/tmp/hypothesis
RUN --network=none --mount=type=cache,target=/root/.cache/uv \
    python -m pytest \
        --basetemp=/tmp/pytest \
        --cov=sambatui \
        --cov-report=term-missing \
        --quiet -p no:cacheprovider \
    && uv sync --frozen --no-dev --no-editable --offline

FROM base AS prod
COPY --from=test /app/.venv /app/.venv
COPY --from=test /opt/python /opt/python
USER app
ENTRYPOINT ["sambatui"]
