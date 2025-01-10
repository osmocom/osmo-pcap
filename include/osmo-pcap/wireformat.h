/*
 * osmo-pcap wireforat
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
#pragma once

#include <stdint.h>
#include <pcap.h>

enum OsmoPcapDataType {
	PKT_LINK_HDR, /* Should send an entire pcap header */
	PKT_LINK_DATA /* Should send one packet */
};

struct osmo_pcap_data {
	uint8_t type;
	uint8_t spare;
	uint16_t len;
	uint8_t data[0];
} __attribute__((packed));

/**
 * struct timeval is not the same across different
 * architectures and for the external format it must
 * be a 32bit value. We have a 2038 issue here?
 */
struct osmo_pcap_pkthdr {
        uint32_t ts_sec;
        uint32_t ts_usec;
	uint32_t caplen;
	uint32_t len;
} __attribute__((packed));
