/*
 * osmo-pcap common
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

#ifndef OSMO_PCAP_COMMON_H
#define OSMO_PCAP_COMMON_H

#include <osmocore/logging.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

enum {
	DPCAP,
	DCLIENT,
	DSERVER,
	DVTY,
	Debug_LastEntry,
};

enum {
	CLIENT_NODE = _LAST_OSMOVTY_NODE + 1,
	SERVER_NODE,
};

extern const struct log_info log_info;
extern const char *osmopcap_copyright;
extern enum node_type osmopcap_go_parent(struct vty *vty);
extern int osmopcap_is_config_node(struct vty *vty, int node);

#endif
