# osmo-pcap distributed network capture

osmo-pcap has been created to collect network traces at different nodes
but store them centrally at a dedicated note for further analysis. This
might be needed for auditing, resolving conflicts, post processing or
debugging a distributed system.

The system consists out of the *osmo-pcap-client* to capture traffic at a
host and *osmo-pcap-server* to receive the traffic, store and rotate the
traffic at a centralized server. There is a shell script to compress
and expire old traces.

## osmo-pcap-client

The *osmo-pcap-client* is using libpcap and has a built-in detector for
the GPRS-NS/BSSGP protocol to exclude user traffic. The client is known
to work on 32/64 bit systems. It can be configured through the VTY and
the minimal config includes the interface to monitor, the pcap filter
to use and the server to send it to.

## osmo-pcap-server

The *osmo-pcap-server* will listen for new TCP connections and then will
receive the data from the client if it is coming from a known/good source
IPv4/port. The server is configured to write one file per client and to
change/rotate the file when the link encapsulation is changing. It can
be configured to rotate the file a given time interval and/or if the
filesize is over a threshold.

The osmo-pcap-server comes with a shell script to rotate and compress
old traces. Currently the configuration parameters (age or amount based)
need to be tuned in the script itself.


## Installation and Configuration

There are Debian, Ubuntu, Raspbian packages available via the excellent
[openSUSE Build Service](https://build.opensuse.org/package/show/network:osmocom:nightly/osmo-pcap).

Please see the *contrib/osmo-pcap-server.cfg* and *contrib/osmo-pcap-client.cfg*
file in the repository

## Running tests

In order to run all tests, do the following:

$ ./configure --enable-external-tests
$ make -j5
$ sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' src/osmo-pcap-client
$ make check

## Wishlist/TODO

- [ ] Add non-blocking TLS (probably GNUtls) support between client and server.
- [ ] Improve the clean-up script, maybe re-write in python with exteral configuration.
- [ ] Add hooks to the server to have an application receive all packages

## Author and License

osmo-pcap has been created by Holger Hans Peter Freyther (holger@freyther.de) and is licensed as AGPLv3+. The author appreciates failure or success reports of using the software.
