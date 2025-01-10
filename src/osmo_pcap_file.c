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
