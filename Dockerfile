# syntax=docker/dockerfile:1
# Match the digest-pinned Docker Hardened Python base used in ica0022.
# Samba requires OS packages, so the shared runtime uses the DHI dev variant.
ARG PYTHON_IMAGE=dhi.io/python:3.14.7-2-debian13-dev@sha256:42cd56dede69350b250398097287cbf1020d0ead0ad8cb4e179bd3bac1a98634
FROM ${PYTHON_IMAGE} AS base
USER root
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates samba-common-bin python3-samba krb5-user bind9-dnsutils \
        libgssapi-krb5-2 passwd
RUN useradd --create-home --uid 1000 app \
    && install -d -o app -g app -m 0700 /home/app/.config/sambatui \
    && samba-tool dns --help >/dev/null \
    && command -v kinit && klist -V && dig -v
ENV HOME=/home/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

FROM base AS build
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev libkrb5-dev
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    python -m venv /opt/uv && /opt/uv/bin/pip install --no-cache-dir uv==0.11.14
ENV PATH="/opt/uv/bin:$PATH" \
    UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy UV_CACHE_DIR=/root/.cache/uv
WORKDIR /opt/sambatui
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    uv sync --frozen --no-dev --extra kerberos --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    uv sync --frozen --no-dev --extra kerberos --no-editable

FROM build AS development
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    uv sync --frozen --extra kerberos
COPY tests ./tests
RUN chown -R app:app /opt/sambatui
ENV PATH="/opt/sambatui/.venv/bin:$PATH" UV_CACHE_DIR=/tmp/uv-cache
USER app
ENTRYPOINT ["sambatui"]

FROM development AS test
ENTRYPOINT ["python", "-m", "pytest"]
CMD ["-q", "-p", "no:cacheprovider", "--basetemp=/tmp/pytest"]

FROM base AS production
COPY --from=build /opt/sambatui/.venv /opt/sambatui/.venv
ENV PATH="/opt/sambatui/.venv/bin:$PATH"
USER app
WORKDIR /home/app
ENTRYPOINT ["sambatui"]
