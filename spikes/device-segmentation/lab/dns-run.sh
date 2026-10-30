#!/bin/bash
# host side: throw-away container, nothing installed on the host
SRC=$1; C=segspike-dns-$$
trap 'docker rm -f $C >/dev/null 2>&1' EXIT
docker run -d --name $C --cap-add NET_ADMIN --memory=512m -v $SRC:/src:ro debian:trixie sleep 300 >/dev/null
docker exec $C sh -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends unbound bind9-dnsutils iproute2 >/dev/null 2>&1; unbound -V | head -1'
docker exec $C bash /src/lab/dns-views.sh
