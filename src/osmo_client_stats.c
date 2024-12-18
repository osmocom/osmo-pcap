/*
 * osmo-pcap-client code
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

#include <osmo-pcap/common.h>
#include <osmo-pcap/osmo_pcap_client.h>

#include "osmopcapconfig.h"

static const struct rate_ctr_desc pcap_client_ctr_desc[] = {
	[CLIENT_CTR_CONNECT]		= { "server:connect",		"Connects to the server" },
	[CLIENT_CTR_BYTES]		= { "captured:bytes",		"Captured bytes        " },
	[CLIENT_CTR_PKTS]		= { "captured:pkts",		"Captured packets      " },
	[CLIENT_CTR_2BIG]		= { "bpf:too_big",		"Captured data too big " },
	[CLIENT_CTR_NOMEM]		= { "client:no_mem",		"No memory available   " },
	[CLIENT_CTR_QERR]		= { "client:queue_err",		"Can not queue data    " },
	[CLIENT_CTR_PERR]		= { "client:pcap_err",		"libpcap error         " },
	[CLIENT_CTR_WERR]		= { "client:write_err",		"Write error           " },
	[CLIENT_CTR_P_RECV]		= { "pcap:recv",		"PCAP received packets " },
	[CLIENT_CTR_P_DROP]		= { "pcap:drop",		"PCAP dropped packets  " },
	[CLIENT_CTR_P_IFDROP]		= { "pcap:ifdrop",		"iface dropped packets " },
};

const struct rate_ctr_group_desc pcap_client_ctr_group_desc = {
	.group_name_prefix		= "pcap:client",
	.group_description		= "PCAP Client statistics",
	.num_ctr			= ARRAY_SIZE(pcap_client_ctr_desc),
	.ctr_desc			= pcap_client_ctr_desc,
	.class_id			= OSMO_STATS_CLASS_GLOBAL,
};
