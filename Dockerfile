# syntax=docker/dockerfile:1
# DHI's dev variant provides apt for Samba's native dependencies.
ARG UV_IMAGE=dhi.io/uv:0.13.7-debian13-dev@sha256:2585792a493eef2a76aa2910cdf62a99c3c8e9a60aabb95724357d9bfe3f3b90
FROM ${UV_IMAGE} AS base
USER root
WORKDIR /app
# Samba's post-install script expects Debian's adm group (absent in DHI).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends passwd \
    && groupadd --system adm \
    && apt-get install -y --no-install-recommends \
        ca-certificates ncurses-base samba-common-bin python3-samba krb5-user bind9-dnsutils \
        libgssapi-krb5-2 \
    && useradd --create-home --uid 1000 app \
    && install -d -o app -g app -m 0700 /home/app/.config/sambatui \
    && samba-tool dns --help >/dev/null
ENV HOME=/home/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

FROM base AS tested
# uv's Python stays separate from Debian's Samba interpreter.
ENV UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PROJECT_ENVIRONMENT=/app/.venv UV_LINK_MODE=copy \
    UV_PYTHON_PREFERENCE=only-managed UV_CACHE_DIR=/root/.cache/uv
RUN --mount=type=bind,target=/source,readonly \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=proxy_ca \
    cp -a /source/. . \
    && apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libkrb5-dev \
    && if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi \
    && uv python install && uv sync --frozen --extra kerberos --no-editable

# The release artifact exists only after tests and coverage pass without network.
RUN --network=none --mount=type=cache,target=/root/.cache/uv \
    HYPOTHESIS_STORAGE_DIRECTORY=/tmp/hypothesis COVERAGE_FILE=/tmp/.coverage \
    /app/.venv/bin/python -m pytest \
        -q -p no:cacheprovider --basetemp=/tmp/pytest \
        --cov=sambatui --cov-report=term-missing \
    && uv sync --offline --frozen --no-dev --extra kerberos --no-editable

FROM base AS production
COPY --from=tested /opt/python /opt/python
COPY --from=tested /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER app
ENTRYPOINT ["sambatui"]
