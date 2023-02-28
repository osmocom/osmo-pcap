/*
 * osmo-pcap common code
 *
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <osmo-pcap/common.h>

#include <osmocom/core/utils.h>

static const struct log_info_cat default_categories[] = {
	[DPCAP] = {
		.name = "DPCAP",
		.description = "PCAP related functionality",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DCLIENT] = {
		.name = "DCLIENT",
		.description = "Client related functionality",
		.color = "\033[1;32m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSERVER] = {
		.name = "DSERVER",
		.description = "Server related functionality",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DVTY] = {
		.name = "DVTY",
		.description = "VTY code",
		.color = "\033[1;34m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DTLS] = {
		.name = "DTLS",
		.description = "TLS code",
		.color = "\033[1;34m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

const char *osmopcap_copyright = 
	"Copyright (C) 2011-2017 Holger Freyther and contributors\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";


int osmopcap_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case CLIENT_NODE:
	case SERVER_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case CLIENT_SERVER_NODE:
		vty->node = CLIENT_NODE;
		vty->index = NULL;
		break;
	default:
		vty->node = CONFIG_NODE;
		break;
	}

	return vty->node;	
}
