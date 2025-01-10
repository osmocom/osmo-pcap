/*
 * Procedures to operate on pcap/pcapng file format
 *
 * (C) 2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <unistd.h>
#include <stdint.h>

/***********************************************************
* Libpcap File Format (.pcap)
* https://wiki.wireshark.org/Development/LibpcapFileFormat
***********************************************************/

#define OSMO_PCAP_FILE_MAGIC 0xa1b2c3d4

int osmo_pcap_file_msgb_append_global_header(struct msgb *msg, uint32_t snaplen, uint32_t linktype);

unsigned int osmo_pcap_file_record_size(const struct pcap_pkthdr *in_hdr);
int osmo_pcap_file_msgb_append_record(struct msgb *msg, const struct pcap_pkthdr *in_hdr, const uint8_t *data);
