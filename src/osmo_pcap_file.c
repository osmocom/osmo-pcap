/*
 * osmo-pcap-client code
 *
 * (C) 2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <pcap/pcap.h>

#include <osmocom/core/msgb.h>

#include <osmo-pcap/osmo_pcap_file.h>
#include <osmo-pcap/common.h>
#include <osmo-pcap/wireformat.h>

/***********************************************************
 * Libpcap File Format (.pcap)
 * https://wiki.wireshark.org/Development/LibpcapFileFormat
 ***********************************************************/

/* Appends a Global Header to msg
 * returns number of bytes appended on success, negative on error */
int osmo_pcap_file_msgb_append_global_header(struct msgb *msg, uint32_t snaplen, uint32_t linktype)
{
	struct pcap_file_header *hdr;

	hdr = (struct pcap_file_header *) msgb_put(msg, sizeof(*hdr));
	hdr->magic = OSMO_PCAP_FILE_MAGIC;
	hdr->version_major = 2;
	hdr->version_minor = 4;
	hdr->thiszone = 0;
	hdr->sigfigs = 0;
	hdr->snaplen = snaplen;
	hdr->linktype = linktype;

	return sizeof(*hdr);
}

/* Get required length to store a given record (packet) */
unsigned int osmo_pcap_file_record_size(const struct pcap_pkthdr *in_hdr)
{
	return sizeof(struct osmo_pcap_pkthdr) + in_hdr->caplen;
}

/* Appends a Record (Packet) Header to msg
 * returns number of bytes appended on success, negative on error */
int osmo_pcap_file_msgb_append_record(struct msgb *msg, const struct pcap_pkthdr *in_hdr, const uint8_t *data)
{
	struct osmo_pcap_pkthdr *hdr;
	uint8_t *pkt_payload;

	hdr = (struct osmo_pcap_pkthdr *) msgb_put(msg, sizeof(*hdr));
	hdr->ts_sec = in_hdr->ts.tv_sec;
	hdr->ts_usec = in_hdr->ts.tv_usec;
	hdr->caplen = in_hdr->caplen;
	hdr->len = in_hdr->len;

	pkt_payload = msgb_put(msg, in_hdr->caplen);
	memcpy(pkt_payload, data, in_hdr->caplen);

	return osmo_pcap_file_record_size(in_hdr);
}


/***********************************************************
 * PCAP Next Generation (pcapng) Capture File Format
 * https://wiki.wireshark.org/Development/PcapNg
 * https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html
 * Related: wireshark.git: wiretap/{pcapng.*, pcapio.c, pcapng_module.h}, wtap_opttypes.h, dumpcap.c
 ***********************************************************/

/* Get required length to store a string option */
static unsigned int osmo_pcapng_file_opt_string_size(const char *str)
{
	size_t str_len = str ? strlen(str) : 0;
	uint8_t pad = str_len % 4;
	/* Each option is padded to 4 bytes: */
	if (pad)
		pad = 4 - pad;
	return sizeof(struct pcapng_option_header) + str_len + pad;
}

/* Append a string option */
static int osmo_pcapng_file_msgb_append_opt_string(struct msgb *msg, uint16_t type, const char *str)
{
	struct pcapng_option_header *opth;
	size_t str_len = str ? strlen(str) : 0;

	opth = (struct pcapng_option_header *)msgb_put(msg, sizeof(*opth));
	opth->type = type;
	opth->value_length = str_len;
	if (str_len > 0)
		memcpy(msgb_put(msg, str_len), str, str_len);

	/* Each option is padded to 4 bytes: */
	uint8_t pad = str_len % 4;
	if (pad) {
		pad = 4 - pad;
		uint8_t *buf = (uint8_t *)msgb_put(msg, pad);
		memset(buf, 0, pad);
	}
	return sizeof(*opth) + opth->value_length + pad;
}

/* Get required length to store a if_filter option.
 * This is a 1 byte enum osmo_pcapng_file_if_filter_type + string */
static unsigned int osmo_pcapng_file_opt_if_filter_string_size(const char *str)
{
	size_t str_len = str ? strlen(str) : 0;
	size_t len = 1 + str_len;
	uint8_t pad = len % 4;
	/* Each option is padded to 4 bytes: */
	if (pad)
		pad = 4 - pad;
	return sizeof(struct pcapng_option_header) + len + pad;
}

/* Append a if_filter option (OPT_IDB_FILTER). */
static int osmo_pcapng_file_msgb_append_opt_if_filter_string(struct msgb *msg, uint16_t type, const char *str)
{
	struct pcapng_option_header *opth;
	uint8_t if_filter_type = IF_FILTER_CAP;
	size_t str_len = str ? strlen(str) : 0;

	opth = (struct pcapng_option_header *)msgb_put(msg, sizeof(*opth));
	opth->type = type;
	opth->value_length = 1 + str_len;
	msgb_put_u8(msg, if_filter_type);
	if (str_len > 0)
		memcpy(msgb_put(msg, str_len), str, str_len);

	/* Each option is padded to 4 bytes: */
	uint8_t pad = opth->value_length % 4;
	if (pad) {
		pad = 4 - pad;
		uint8_t *buf = (uint8_t *)msgb_put(msg, pad);
		memset(buf, 0, pad);
	}
	return sizeof(*opth) + opth->value_length + pad;
}

/* Get required length to store a OPT_EOFOPT option */
static unsigned int osmo_pcapng_file_opt_eofopt_size(void)
{
	return sizeof(struct pcapng_option_header);
}

/* Append a OPT_EOFOPT option */
static int osmo_pcapng_file_msgb_append_opt_eofopt(struct msgb *msg)
{
	struct pcapng_option_header *opth;

	opth = (struct pcapng_option_header *)msgb_put(msg, sizeof(*opth));
	opth->type = OPT_EOFOPT;
	opth->value_length = 0;

	return sizeof(*opth);
}

/* Get required length to store a given record (packet) */
unsigned int osmo_pcapng_file_shb_size(const struct osmo_pcapng_file_shb_pars *pars)
{
	uint32_t block_total_len = sizeof(struct pcapng_block_header) +
				   sizeof(struct pcapng_section_header_block) +
				   sizeof(uint32_t);
	block_total_len += osmo_pcapng_file_opt_string_size(pars->hardware);
	block_total_len += osmo_pcapng_file_opt_string_size(pars->os);
	block_total_len += osmo_pcapng_file_opt_string_size(pars->userappl);
	block_total_len += osmo_pcapng_file_opt_eofopt_size();
	return block_total_len;
}

/* Appends a Section Header Block (SHB) to msg
 * returns number of bytes appended on success, negative on error */
int osmo_pcapng_file_msgb_append_shb(struct msgb *msg, const struct osmo_pcapng_file_shb_pars *pars)
{
	struct pcapng_block_header *bh;
	struct pcapng_section_header_block *shb;
	uint8_t *footer_len;
	uint32_t block_total_len = osmo_pcapng_file_shb_size(pars);

	bh = (struct pcapng_block_header *)msgb_put(msg, sizeof(*bh));
	bh->block_type = BLOCK_TYPE_SHB;
	bh->block_total_length = block_total_len;

	/* write block fixed content */
	shb = (struct pcapng_section_header_block *)msgb_put(msg, sizeof(*shb));
	shb->magic = 0x1A2B3C4D;
	shb->version_major = 1;
	shb->version_minor = 0;
	shb->section_length = -1;

	/* Options (variable) */
	osmo_pcapng_file_msgb_append_opt_string(msg, OPT_SHB_HARDWARE, pars->hardware);
	osmo_pcapng_file_msgb_append_opt_string(msg, OPT_SHB_OS, pars->os);
	osmo_pcapng_file_msgb_append_opt_string(msg, OPT_SHB_USERAPPL, pars->userappl);
	osmo_pcapng_file_msgb_append_opt_eofopt(msg);

	/* SHB Block Total Length */
	footer_len = (uint8_t *)msgb_put(msg, sizeof(uint32_t));
	memcpy(footer_len, &block_total_len, sizeof(uint32_t));

	return block_total_len;
}

unsigned int osmo_pcapng_file_idb_size(const struct osmo_pcapng_file_idb_pars *pars)
{
	uint32_t block_total_len = sizeof(struct pcapng_block_header) +
				   sizeof(struct pcapng_iface_descr_block) +
				   sizeof(uint32_t);
	block_total_len += osmo_pcapng_file_opt_string_size(pars->name);
	block_total_len += osmo_pcapng_file_opt_if_filter_string_size(pars->filter);
	block_total_len += osmo_pcapng_file_opt_eofopt_size();
	return block_total_len;
}

int osmo_pcapng_file_msgb_append_idb(struct msgb *msg, const struct osmo_pcapng_file_idb_pars *pars)
{
	struct pcapng_block_header *bh;
	struct pcapng_iface_descr_block *idb;
	uint8_t *footer_len;
	uint32_t block_total_len = osmo_pcapng_file_idb_size(pars);

	bh = (struct pcapng_block_header *)msgb_put(msg, sizeof(*bh));
	bh->block_type = BLOCK_TYPE_IDB;
	bh->block_total_length = block_total_len;

	/* write block fixed content */
	idb = (struct pcapng_iface_descr_block *)msgb_put(msg, sizeof(*idb));
	idb->linktype = pars->link_type;
	idb->reserved = 0;
	idb->snaplen = pars->snap_len;

	/* Options (variable) */
	osmo_pcapng_file_msgb_append_opt_string(msg, OPT_IDB_NAME, pars->name);
	osmo_pcapng_file_msgb_append_opt_if_filter_string(msg, OPT_IDB_FILTER, pars->filter);
	osmo_pcapng_file_msgb_append_opt_eofopt(msg);

	/* IDB Block Total Length */
	footer_len = (uint8_t *)msgb_put(msg, sizeof(uint32_t));
	memcpy(footer_len, &block_total_len, sizeof(uint32_t));

	return block_total_len;
}

unsigned int osmo_pcapng_file_epb_size(const struct osmo_pcapng_file_epb_pars *pars)
{
	uint32_t block_total_len = sizeof(struct pcapng_block_header) +
				   sizeof(struct pcapng_enhanced_packet_block) +
				   pars->captured_len +
				   sizeof(uint32_t);
	/* Packet data is padded to 4 bytes: */
	uint8_t pad = pars->captured_len % 4;
	if (pad)
		block_total_len += (4 - pad);

	/* TODO: other Options */
	block_total_len += osmo_pcapng_file_opt_eofopt_size();
	return block_total_len;
}

int osmo_pcapng_file_msgb_append_epb(struct msgb *msg, const struct osmo_pcapng_file_epb_pars *pars)
{
	struct pcapng_block_header *bh;
	struct pcapng_enhanced_packet_block *epb;
	uint8_t *footer_len;
	uint32_t block_total_len = osmo_pcapng_file_epb_size(pars);

	bh = (struct pcapng_block_header *)msgb_put(msg, sizeof(*bh));
	bh->block_type = BLOCK_TYPE_EPB;
	bh->block_total_length = block_total_len;

	/* write block fixed content */
	epb = (struct pcapng_enhanced_packet_block *)msgb_put(msg, sizeof(*epb));
	epb->interface_id = pars->interface_id;
	epb->timestamp_high = pars->timestamp_usec >> 32;
	epb->timestamp_low = (uint32_t)(pars->timestamp_usec & 0xffffffff);
	epb->captured_len = pars->captured_len;
	epb->packet_len = pars->packet_len;

	/* Packet Data */
	if (pars->captured_len > 0)
		memcpy(msgb_put(msg, pars->captured_len), pars->captured_data, pars->captured_len);

	/* Each option is padded to 4 bytes: */
	uint8_t pad = pars->captured_len % 4;
	if (pad) {
		pad = 4 - pad;
		uint8_t *buf = (uint8_t *)msgb_put(msg, pad);
		memset(buf, 0, pad);
	}

	/* Options (variable) */
	osmo_pcapng_file_msgb_append_opt_eofopt(msg);

	/* EPB Block Total Length */
	footer_len = (uint8_t *)msgb_put(msg, sizeof(uint32_t));
	memcpy(footer_len, &block_total_len, sizeof(uint32_t));

	return block_total_len;
}
