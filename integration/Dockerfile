FROM dhi.io/debian-base:trixie-debian13-dev@sha256:94571f3dc07fbc7166f6f1cbf1fe068a7647198ee2554e6b90d59a68cc8b053c
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends passwd \
    && groupadd --system adm && groupadd --system users \
    && apt-get install -y --no-install-recommends \
    samba-ad-dc samba-ad-provision samba-vfs-modules samba-common-bin \
    python3 openssl krb5-user ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY server.sh /server.sh
ENTRYPOINT ["sh", "/server.sh"]
