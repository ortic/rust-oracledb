#!/usr/bin/env bash
# Adds a TLS (TCPS) listener on port 2484 to a gvenzl/oracle-free container,
# with a self-signed certificate for localhost, so the tests can run over
# TLS. Writes the certificate as <client dir>/ewallet.pem for the tests'
# wallet location (RSO_TEST_WALLET_LOCATION).
#
#   enable-tcps.sh <container> <client dir>
#
# Needs Java: Oracle's wallet tool (orapki) comes from Maven Central, as the
# image has no Java or PKI libraries.
set -euo pipefail
container=$1
client_dir=$2
work=$(mktemp -d)
password=Wallet_$RANDOM$RANDOM

curl -sfL -o "$work/oraclepki.jar" \
  https://repo1.maven.org/maven2/com/oracle/database/security/oraclepki/23.8.0.25.04/oraclepki-23.8.0.25.04.jar
orapki() { java -cp "$work/oraclepki.jar" oracle.security.pki.textui.OraclePKITextUI "$@"; }
orapki wallet create -wallet "$work/wallet" -pwd "$password" -auto_login
orapki wallet add -wallet "$work/wallet" -dn "CN=localhost" -keysize 2048 \
  -self_signed -validity 30 -addext_san DNS:localhost,IPV4Address:127.0.0.1 \
  -pwd "$password"
mkdir -p "$client_dir"
orapki wallet export -wallet "$work/wallet" -dn "CN=localhost" \
  -cert "$client_dir/ewallet.pem" -pwd "$password"

docker exec -u root "$container" mkdir -p /opt/oracle/wallet
docker cp "$work/wallet/cwallet.sso" "$container:/opt/oracle/wallet/"
docker cp "$work/wallet/ewallet.p12" "$container:/opt/oracle/wallet/"
docker exec -u root "$container" bash -c \
  'chown -R oracle:oinstall /opt/oracle/wallet && chmod 600 /opt/oracle/wallet/*'
docker exec "$container" bash -c '
  set -e
  cd "$ORACLE_HOME/network/admin"
  sed -i "s|(ADDRESS = (PROTOCOL = TCP)(HOST=)(PORT = 1521))|&\n      (ADDRESS = (PROTOCOL = TCPS)(HOST=)(PORT = 2484))|" listener.ora
  wallet="WALLET_LOCATION = (SOURCE = (METHOD = FILE)(METHOD_DATA = (DIRECTORY = /opt/oracle/wallet)))"
  printf "%s\nSSL_CLIENT_AUTHENTICATION = FALSE\n" "$wallet" | tee -a listener.ora >> sqlnet.ora
  lsnrctl stop > /dev/null
  lsnrctl start > /dev/null
  echo "alter system register;" | sqlplus -s / as sysdba > /dev/null
'
# The services register with the new listener within seconds.
for _ in $(seq 30); do
  if docker exec "$container" lsnrctl status | grep -qi 'service "freepdb1"'; then
    rm -rf "$work"
    exit 0
  fi
  sleep 2
done
echo "FREEPDB1 didn't register with the listener" >&2
exit 1
