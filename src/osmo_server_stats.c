/*
 * osmo-pcap-server code
 *
 * (C) 2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2011-2016 by Holger Hans Peter Freyther <holger@moiji-mobile.com>
 * (C) 2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>

#include <osmo-pcap/common.h>
#include <osmo-pcap/osmo_pcap_server.h>
#include <osmo-pcap/osmo_tls.h>

static const struct rate_ctr_desc pcap_peer_ctr_desc[] = {
	[PEER_CTR_CONNECT]		= { "peer:connect",	"Connect of a peer   " },
	[PEER_CTR_BYTES]		= { "peer:bytes",	"Received bytes      " },
	[PEER_CTR_PKTS]			= { "peer:pkts",	"Received packets    " },
	[PEER_CTR_PROTATE]		= { "peer:file_rotated", "Capture file rotated" },
};

static const struct rate_ctr_desc pcap_server_ctr_desc[] = {
	[SERVER_CTR_CONNECT]		= { "server:connect",	"Connect of a peer   " },
	[SERVER_CTR_BYTES]		= { "server:bytes",	"Received bytes      " },
	[SERVER_CTR_PKTS]		= { "server:pkts",	"Received packets    " },
	[SERVER_CTR_PROTATE]		= { "server:file_rotated", "Capture file rotated" },
	[SERVER_CTR_NOCLIENT]		= { "server:no_client", "Unknown connected   " },
};

const struct rate_ctr_group_desc pcap_peer_group_desc = {
	.group_name_prefix		= NULL,	/* will be dynamically patched */
	.group_description		= "PCAP peer statistics",
	.num_ctr			= ARRAY_SIZE(pcap_peer_ctr_desc),
	.ctr_desc			= pcap_peer_ctr_desc,
	.class_id			= OSMO_STATS_CLASS_PEER,
};

const struct rate_ctr_group_desc pcap_server_group_desc = {
	.group_name_prefix		= "pcap:server",
	.group_description		= "PCAP Server global statistics",
	.num_ctr			= ARRAY_SIZE(pcap_server_ctr_desc),
	.ctr_desc			= pcap_server_ctr_desc,
	.class_id			= OSMO_STATS_CLASS_GLOBAL,
};
