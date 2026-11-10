#!/bin/sh
# Disposable server fixture only; never run on the host.
set -eu
[ "${SAMBATUI_SERVER_FIXTURE:-}" = DISPOSABLE ] || { echo 'Test fixture only; use integration/run.sh' >&2; exit 1; }
[ -e /.dockerenv ] || { echo 'Refusing host provisioning' >&2; exit 1; }
mkdir -p /tmp/native-ad
printf 'sambatui isolated disposable lab\n' > /tmp/native-ad/disposable.marker
/usr/bin/python3 - <<'PY'
from samba.provision import provision
from samba.auth import system_session
import logging
provision(logging.getLogger('native-test'), system_session(), targetdir='/tmp/native-ad/domain', realm='LAB.INVALID', domain='LAB', hostname='dc', hostip='127.0.0.1', users='app', serverrole='active directory domain controller', dns_backend='SAMBA_INTERNAL', adminpass='Disposable-test-only_42!', skip_sysvolacl=True)
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout /tmp/native-ad/key.pem -out /tmp/native-ad/cert.pem -subj /CN=dc.lab.invalid -addext subjectAltName=DNS:dc.lab.invalid,IP:127.0.0.1
/usr/bin/python3 - <<'PY'
from pathlib import Path
p=Path('/tmp/native-ad/domain/etc/smb.conf')
p.write_text(p.read_text().replace('[global]', '''[global]
 interfaces = 127.0.0.1
 bind interfaces only = yes
 tls enabled = yes
 tls keyfile = /tmp/native-ad/key.pem
 tls certfile = /tmp/native-ad/cert.pem
 tls cafile = /tmp/native-ad/cert.pem
 dns forwarder =
'''))
PY
printf '127.0.0.1 dc.lab.invalid\n' >> /etc/hosts
cat > /tmp/native-ad/krb5.conf <<'EOF'
[libdefaults]
 default_realm = LAB.INVALID
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
[realms]
 LAB.INVALID = {
 kdc = 127.0.0.1
 }
EOF
samba-tool user create Reader 'Disposable-test-only_42!' --configfile=/tmp/native-ad/domain/etc/smb.conf
samba-tool user create Whitespace '  Disposable-test-only_42!  ' --configfile=/tmp/native-ad/domain/etc/smb.conf
samba -i --no-process-group --configfile=/tmp/native-ad/domain/etc/smb.conf &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" || true' TERM INT EXIT
tries=0
until printf 'Disposable-test-only_42!\n' | KRB5_CONFIG=/tmp/native-ad/krb5.conf KRB5CCNAME=FILE:/tmp/native-ad/reader.ccache kinit Reader@LAB.INVALID; do
    tries=$((tries + 1)); [ "$tries" -lt 30 ] || exit 1
    sleep 1
done
PASSWD='Disposable-test-only_42!' samba-tool dns zonecreate 127.0.0.1 2.0.192.in-addr.arpa -U 'LAB\Administrator'
printf 'ready\n' > /tmp/native-ad/ready
wait "$pid"
