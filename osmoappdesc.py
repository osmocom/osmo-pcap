#!/usr/bin/env python3

# (C) 2016 by Holger Hans Peter Freyther
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

app_configs = {
    "osmo-pcap-client": ["doc/examples/osmo-pcap-client/osmo-pcap-client.cfg",
                         "doc/examples/osmo-pcap-client/osmo-pcap-client-tls.cfg"],
    "osmo-pcap-server": ["doc/examples/osmo-pcap-server/osmo-pcap-server.cfg",
                         "doc/examples/osmo-pcap-server/osmo-pcap-server-tls.cfg"]
}

apps = [
    (4228, "src/osmo-pcap-server", "OsmoPCAPServer", "osmo-pcap-server"),
    (4227, "src/osmo-pcap-client", "OsmoPCAPClient", "osmo-pcap-client"),
        ]

vty_command = ["src/osmo-pcap-server", "-c", "doc/examples/osmo-pcap-server/osmo-pcap-server.cfg"]
vty_app = apps[0]


