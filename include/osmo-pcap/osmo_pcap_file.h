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

enum osmo_pcap_fmt {
	OSMO_PCAP_FMT_PCAP = 0,
	OSMO_PCAP_FMT_PCAPNG,
};

/***********************************************************
* Libpcap File Format (.pcap)
* https://wiki.wireshark.org/Development/LibpcapFileFormat
***********************************************************/

#define OSMO_PCAP_FILE_MAGIC 0xa1b2c3d4

int osmo_pcap_file_msgb_append_global_header(struct msgb *msg, uint32_t snaplen, uint32_t linktype);

unsigned int osmo_pcap_file_record_size(const struct pcap_pkthdr *in_hdr);
int osmo_pcap_file_msgb_append_record(struct msgb *msg, const struct pcap_pkthdr *in_hdr, const uint8_t *data);

/***********************************************************
 * PCAP Next Generation (pcapng) Capture File Format
 * https://wiki.wireshark.org/Development/PcapNg
 * https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html
 * Related: wireshark.git: wiretap/{pcapng.*, pcapio.c, pcapng_module.h}, wtap_opttypes.h, dumpcap.c
 ***********************************************************/

#define OSMO_PCAPNG_FILE_MAGIC 0x1A2B3C4D
#define OSMO_PCAPNG_FILE_MAGIC_SWAPPED 0x4D3C2B1A

#define BLOCK_TYPE_SHB	0x0A0D0D0A /* Section Header Block */
#define BLOCK_TYPE_IDB	0x00000001 /* Interface Description Block */
#define BLOCK_TYPE_PB	0x00000002 /* Packet Block (obsolete) */
#define BLOCK_TYPE_SPB	0x00000003 /* Simple Packet Block */
#define BLOCK_TYPE_EPB	0x00000006 /* Enhanced Packet Block */

/* Options for all blocks */
#define OPT_EOFOPT		0
#define OPT_COMMENT		1
/* Section Header block (SHB) */
#define OPT_SHB_HARDWARE	2
#define OPT_SHB_OS		3
#define OPT_SHB_USERAPPL	4

/* Interface Description block (IDB) */
#define OPT_IDB_NAME		2
#define OPT_IDB_DESCRIPTION	3
#define OPT_IDB_IP4ADDR		4
#define OPT_IDB_IP6ADDR		5
#define OPT_IDB_MACADDR		6
#define OPT_IDB_FILTER		11

/* filter Option: */
enum osmo_pcapng_file_if_filter_type {
	IF_FILTER_CAP = 0, /* pcap filter string */
	IF_FILTER_BPF = 1  /* BPF program */
};

/* pcapng: common block header file encoding for every block type */
struct pcapng_block_header {
	uint32_t block_type;
	uint32_t block_total_length;
	uint8_t block_body[0]; /* x bytes block_body */
	/* uint32_t block_total_length */
} __attribute__((packed));

struct pcapng_option_header {
	uint16_t type;
	uint16_t value_length;
} __attribute__((packed));

/* pcapng: section header block file encoding */
struct pcapng_section_header_block {
	/* pcapng_block_header_t */
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	uint64_t section_length; /* might be -1 for unknown */
	/* ... Options ... */
} __attribute__((packed));

/* pcapng: interface description block file encoding */
struct pcapng_iface_descr_block {
	uint16_t linktype;
	uint16_t reserved;
	uint32_t snaplen;
	/* ... Options ... */
} __attribute__((packed));

/* pcapng: enhanced packet block file encoding */
struct pcapng_enhanced_packet_block {
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_len;
	uint32_t packet_len;
	uint8_t packet_data[0]; /* ... Packet Data ... */
	/* ... Padding ... */
	/* ... Options ... */
} __attribute__((packed));

/* Helper APIs to encode blocks: */

struct osmo_pcapng_file_shb_pars {
	const char *hardware;
	const char *os;
	const char *userappl;
};
unsigned int osmo_pcapng_file_shb_size(const struct osmo_pcapng_file_shb_pars *pars);
int osmo_pcapng_file_msgb_append_shb(struct msgb *msg, const struct osmo_pcapng_file_shb_pars *pars);

struct osmo_pcapng_file_idb_pars {
	const char *name;
	const char *filter;
	int link_type;
	int snap_len;
};
unsigned int osmo_pcapng_file_idb_size(const struct osmo_pcapng_file_idb_pars *pars);
int osmo_pcapng_file_msgb_append_idb(struct msgb *msg, const struct osmo_pcapng_file_idb_pars *pars);

struct osmo_pcapng_file_epb_pars {
	uint64_t timestamp_usec;
	uint32_t interface_id;
	const uint8_t *captured_data;
	uint32_t captured_len;
	uint32_t packet_len;
};
unsigned int osmo_pcapng_file_epb_size(const struct osmo_pcapng_file_epb_pars *pars);
int osmo_pcapng_file_msgb_append_epb(struct msgb *msg, const struct osmo_pcapng_file_epb_pars *pars);
