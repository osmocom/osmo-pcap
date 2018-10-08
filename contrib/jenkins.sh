#!/usr/bin/env bash

set -ex

rm -rf deps/install
mkdir deps || true
cd deps
osmo-deps.sh libosmocore

cd libosmocore
autoreconf --install --force
./configure --prefix=$PWD/../install
$MAKE $PARALLEL_MAKE install

cd ../../
autoreconf --install --force
PCAP_LIBS="-lpcap" PCAP_CFLAGS="" PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig ./configure --with-pcap-config=/bin/true --enable-sanitize --enable-werror
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig $MAKE $PARALLEL_MAKE
DISTCHECK_CONFIGURE_FLAGS="--with-pcap-config=/bin/true" PCAP_LIBS="-lpcap" PCAP_CFLAGS="" PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig LD_LIBRARY_PATH=$PWD/deps/install/lib $MAKE distcheck
