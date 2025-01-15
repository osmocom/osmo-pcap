#!/usr/bin/env bash
# jenkins build helper script for osmo-pcap.  This is how we build on jenkins.osmocom.org

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi

set -ex


base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
osmo-build-dep.sh libosmocore "" '--disable-doxygen --enable-gnutls'
osmo-build-dep.sh libosmo-netif "" --disable-doxygen

# Additional configure options and depends
CONFIG=""
if [ "$WITH_MANUALS" = "1" ]; then
	osmo-build-dep.sh osmo-gsm-manuals
	CONFIG="--enable-manuals"
fi

set +x
echo
echo
echo
echo " =============================== osmo-pcap ==============================="
echo
set -x


cd "$base"
autoreconf --install --force
PCAP_LIBS="-lpcap" PCAP_CFLAGS="" ./configure \
	--with-pcap-config=/bin/true \
	--enable-sanitize \
	--enable-werror \
	$CONFIG
$MAKE $PARALLEL_MAKE
$MAKE check || cat-testlogs.sh
DISTCHECK_CONFIGURE_FLAGS="--with-pcap-config=/bin/true $CONFIG" \
        PCAP_LIBS="-lpcap" PCAP_CFLAGS="" \
        $MAKE distcheck || cat-testlogs.sh

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
	make -C "$base/doc/manuals" publish
fi

$MAKE maintainer-clean

osmo-clean-workspace.sh
