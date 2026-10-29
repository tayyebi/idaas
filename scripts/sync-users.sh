#!/bin/sh
# Snapshot the system account database into ./data/etc for the idaas container.
#
# - READS host /etc only (nothing on the host is modified)
# - WRITES only inside ./data
# - /etc/shadow is root-only, so run with sudo
#
# After a snapshot changes, restart the container: bind-mounted files keep
# pointing at the old version until the container is restarted.
set -eu

SRC_PASSWD="${IDAAS_SYNC_PASSWD:-/etc/passwd}"
SRC_GROUP="${IDAAS_SYNC_GROUP:-/etc/group}"
SRC_SHADOW="${IDAAS_SYNC_SHADOW:-/etc/shadow}"

die() { echo "sync-users: $*" >&2; exit 1; }

[ -r "$SRC_PASSWD" ] || die "cannot read $SRC_PASSWD"
[ -r "$SRC_GROUP" ] || die "cannot read $SRC_GROUP"
[ -r "$SRC_SHADOW" ] || die "cannot read $SRC_SHADOW (re-run with sudo)"

mkdir -p data/etc
chmod 700 data/etc

changed=0
snap() { # snap <src> <dst> <mode>
    if [ ! -f "$2" ] || ! cmp -s "$1" "$2"; then
        install -m "$3" "$1" "$2"
        changed=1
    fi
}
snap "$SRC_PASSWD" data/etc/passwd 0644
snap "$SRC_GROUP"  data/etc/group  0644
snap "$SRC_SHADOW" data/etc/shadow 0600

if [ ! -f data/clients.conf ]; then
    if [ -f clients.example.conf ]; then
        cp clients.example.conf data/clients.conf
        chmod 0600 data/clients.conf
        echo "sync-users: created data/clients.conf from clients.example.conf (edit it!)"
    else
        echo "sync-users: warning: data/clients.conf missing and no example found" >&2
    fi
fi

if [ "$changed" = 1 ]; then
    echo "sync-users: changed — restart the idaas container to pick it up"
else
    echo "sync-users: unchanged"
fi
