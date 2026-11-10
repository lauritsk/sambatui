ARG BASE_IMAGE=dhi.io/debian-base:trixie-debian13-dev
ARG BASE_DIGEST=sha256:94571f3dc07fbc7166f6f1cbf1fe068a7647198ee2554e6b90d59a68cc8b053c
FROM ${BASE_IMAGE}@${BASE_DIGEST}

# Bound repository retries and requests; the Go runner bounds the entire build.
ARG DEBIAN_FRONTEND=noninteractive
RUN printf '%s\n' 'Acquire::Retries "3";' \
        'Acquire::http::Timeout "30";' 'Acquire::https::Timeout "30";' \
        > /etc/apt/apt.conf.d/99fixture-bounds \
    && apt-get update \
    && apt-get install --yes --no-install-recommends passwd \
    && groupadd --system adm \
    && groupadd --system users \
    && apt-get install --yes --no-install-recommends \
        samba-ad-dc samba-ad-provision samba-vfs-modules samba-common-bin \
        python3 openssl krb5-user ca-certificates \
    && rm --recursive --force /var/lib/apt/lists/*

COPY server.py server_test.py /opt/sambatui/
RUN /usr/bin/python3 -I -m unittest discover \
    --start-directory /opt/sambatui --pattern server_test.py
ENTRYPOINT ["/usr/bin/python3", "-I", "-u", "/opt/sambatui/server.py"]
