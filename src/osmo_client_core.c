/*
 * osmo-pcap-client code
 *
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

#define _DEFAULT_SOURCE
#include <osmo-pcap/osmo_pcap_client.h>
#include <osmo-pcap/common.h>

#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/protocol/gsm_08_16.h>
#include <osmocom/gprs/protocol/gsm_08_18.h>

#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/talloc.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <limits.h>

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

#define IP_LEN		sizeof(struct ip)
#define UDP_LEN		sizeof(struct udphdr)
#define NS_LEN		1

static int check_gprs(const u_char *data, bpf_u_int32 len)
{
	struct tlv_parsed tp;
	struct gprs_ns_hdr *hdr = (struct gprs_ns_hdr *) data;
	struct bssgp_ud_hdr *bssgp_hdr;
	uint8_t llc_sapi;

	switch (hdr->pdu_type) {
	case NS_PDUT_UNITDATA:
		break;
	default:
		return 1;
	}

	len -= sizeof(*hdr);

	/* NS_PDUT_UNITDATA from here.. */
	/* skip NS SDU control bits and BVCI */
	if (len < 3)
		return 1;
	len -= 3;

	/* Check if the BSSGP UD hdr fits */
	if (len < sizeof(*bssgp_hdr))
		return 1;
	bssgp_hdr = (struct bssgp_ud_hdr *) &hdr->data[3];

	/* BVC flow control is creating too much noise. Drop it  */
	if (bssgp_hdr->pdu_type == BSSGP_PDUT_FLOW_CONTROL_BVC
		|| bssgp_hdr->pdu_type == BSSGP_PDUT_FLOW_CONTROL_BVC_ACK)
		return 0;

	/* We only need to check UL/DL messages for the sapi */
	if (bssgp_hdr->pdu_type != BSSGP_PDUT_DL_UNITDATA
		&& bssgp_hdr->pdu_type != BSSGP_PDUT_UL_UNITDATA)
		return 1;
	len -= sizeof(*bssgp_hdr);

	/* now parse the rest of the IEs */
	memset(&tp, 0, sizeof(tp));
	if (bssgp_tlv_parse(&tp, &bssgp_hdr->data[0], len) < 0)
		return 1;

	if (!TLVP_PRESENT(&tp, BSSGP_IE_LLC_PDU))
		return 1;
	if (TLVP_LEN(&tp, BSSGP_IE_LLC_PDU) < 1)
		return 1;

	llc_sapi = TLVP_VAL(&tp, BSSGP_IE_LLC_PDU)[0] & 0x0f;
	/* Skip user data 3, 5, 9, 11 */
	if (llc_sapi == 3 || llc_sapi == 5 || llc_sapi == 9 || llc_sapi == 11)
		return 0;
	return 1;
}

static int can_forward_packet(
			struct osmo_pcap_client *client,
			struct osmo_pcap_handle *ph,
			struct pcap_pkthdr *hdr,
			const u_char *data)
{
	int ll_type;
	int offset;
	struct ip *ip_hdr;
	const u_char *ip_data;
	const u_char *udp_data;
	const u_char *payload_data;
	bpf_u_int32 payload_len;

	if (!client->gprs_filtering)
		return 1;

	ll_type = pcap_datalink(ph->handle);
	switch (ll_type) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_LINUX_SLL:
		offset = 16;
		break;
	default:
		LOGPH(ph, LOGL_ERROR, "LL type %d/%s not handled.\n",
		      ll_type, pcap_datalink_val_to_name(ll_type));
		return 1;
	}

	/* Check if this can be a full UDP frame with NS */
	if (offset + IP_LEN + UDP_LEN + NS_LEN > hdr->caplen)
		return 1;

	ip_data = data + offset;
	ip_hdr = (struct ip *) ip_data;

	/* Only handle IPv4 */
	if (ip_hdr->ip_v != 4)
		return 1;
	/* Only handle UDP */
	if (ip_hdr->ip_p != 17)
		return 1;

	udp_data = ip_data + IP_LEN;
	payload_data = udp_data + UDP_LEN;
	payload_len = hdr->caplen - offset - IP_LEN - UDP_LEN;

	return check_gprs(payload_data, payload_len);
}


static int pcap_read_cb(struct osmo_fd *fd, unsigned int what)
{
	struct osmo_pcap_handle *ph = fd->data;
	struct osmo_pcap_client *client = ph->client;
	struct osmo_pcap_client_conn *conn;
	struct pcap_pkthdr hdr;
	const u_char *data;

	data = pcap_next(ph->handle, &hdr);
	if (!data) {
		rate_ctr_inc2(ph->ctrg, PH_CTR_PERR);
		rate_ctr_inc2(client->ctrg, CLIENT_CTR_PERR);
		return -1;
	}

	if (!can_forward_packet(client, ph, &hdr, data))
		return 0;

	llist_for_each_entry(conn, &client->conns, entry)
		osmo_client_conn_send_data(conn, &hdr, data);
	return 0;
}

static inline u_int P_CAP_UINT_MAX()
{
	u_int val = 0;
	return ~val;
}

static uint64_t get_psbl_wrapped_ctr(u_int old_val, u_int new_val)
{
	uint64_t ret;
	/*
	* Wrapped..
	* So let's at from N to XYZ_MAX
	* and then from 0 to new_val
	* Only issue is we don't know sizeof(u_int)
	*/
	if (old_val > new_val) {
		ret = P_CAP_UINT_MAX() - old_val;
		ret += new_val;
		return ret;
	}
	/* old_val <= new_val, Just increment it */
	return new_val - old_val;
}

static void pcap_check_stats_cb(void *_ph)
{
	struct pcap_stat stat;
	struct osmo_pcap_handle *ph = _ph;
	struct osmo_pcap_client *client = ph->client;
	int rc;
	uint64_t inc;

	/* reschedule */
	osmo_timer_schedule(&ph->pcap_stat_timer, 10, 0);

	memset(&stat, 0, sizeof(stat));
	rc = pcap_stats(ph->handle, &stat);
	if (rc != 0) {
		LOGPH(ph, LOGL_ERROR, "Failed to query pcap stats: %s\n", pcap_geterr(ph->handle));
		rate_ctr_inc2(ph->ctrg, PH_CTR_PERR);
		rate_ctr_inc2(client->ctrg, CLIENT_CTR_PERR);
		return;
	}

	inc = get_psbl_wrapped_ctr(ph->last_ps_recv, stat.ps_recv);
	rate_ctr_add2(ph->ctrg, PH_CTR_P_RECV, inc);
	rate_ctr_add2(client->ctrg, CLIENT_CTR_P_RECV, inc);
	ph->last_ps_recv = stat.ps_recv;

	inc = get_psbl_wrapped_ctr(ph->last_ps_drop, stat.ps_drop);
	rate_ctr_add2(ph->ctrg, PH_CTR_P_DROP, inc);
	rate_ctr_add2(client->ctrg, CLIENT_CTR_P_DROP, inc);
	ph->last_ps_drop = stat.ps_drop;

	inc = get_psbl_wrapped_ctr(ph->last_ps_ifdrop, stat.ps_ifdrop);
	rate_ctr_add2(ph->ctrg, PH_CTR_P_IFDROP, inc);
	rate_ctr_add2(client->ctrg, CLIENT_CTR_P_IFDROP, inc);
	ph->last_ps_ifdrop = stat.ps_ifdrop;
}

static int osmo_pcap_handle_install_filter(struct osmo_pcap_handle *ph)
{
	int rc;
	pcap_freecode(&ph->bpf);

	if (!ph->handle) {
		LOGPH(ph, LOGL_NOTICE, "Filter will only be applied later\n");
		return 0;
	}

	rc = pcap_compile(ph->handle, &ph->bpf,
			  ph->client->filter_string, 1, PCAP_NETMASK_UNKNOWN);
	if (rc != 0) {
		LOGPH(ph, LOGL_ERROR, "Failed to compile the filter: %s\n",
		     pcap_geterr(ph->handle));
		return rc;
	}

	rc = pcap_setfilter(ph->handle, &ph->bpf);
	if (rc != 0) {
		LOGPH(ph, LOGL_ERROR, "Failed to set the filter on the interface: %s\n", pcap_geterr(ph->handle));
		pcap_freecode(&ph->bpf);
		return rc;
	}
	LOGPH(ph, LOGL_INFO, "Filter applied\n");

	return rc;
}

int osmo_client_start_capture(struct osmo_pcap_client *client)
{
	struct osmo_pcap_handle *ph;
	struct osmo_pcap_client_conn *conn;
	int rc;

	llist_for_each_entry(ph, &client->handles, entry) {
		rc = osmo_pcap_handle_start_capture(ph);
		if (rc < 0)
			return rc;
	}

	llist_for_each_entry(conn, &client->conns, entry)
		osmo_client_conn_send_link(conn);
	return 0;
}

int osmo_client_filter(struct osmo_pcap_client *client, const char *filter)
{
	struct osmo_pcap_handle *ph;
	int rc = 0;
	talloc_free(client->filter_string);
	client->filter_string = talloc_strdup(client, filter);

	llist_for_each_entry(ph, &client->handles, entry)
		rc |= osmo_pcap_handle_install_filter(ph);

	return rc;
}

struct osmo_pcap_client *osmo_pcap_client_alloc(void *tall_ctx)
{
	struct osmo_pcap_client *client;
	client = talloc_zero(tall_ctx, struct osmo_pcap_client);
	if (!client)
		return NULL;

	client->snaplen = DEFAULT_SNAPLEN;
	INIT_LLIST_HEAD(&client->handles);
	INIT_LLIST_HEAD(&client->conns);

	/* initialize the stats interface */
	client->ctrg = rate_ctr_group_alloc(pcap_client, &pcap_client_ctr_group_desc, 0);
	if (!client->ctrg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate rate ctr\n");
		goto ret_free;
	}

	return client;

ret_free:
	talloc_free(client);
	return NULL;
}

void osmo_client_conn_free(struct osmo_pcap_client_conn *conn)
{
	osmo_client_conn_disconnect(conn);
	llist_del(&conn->entry);
	talloc_free(conn);
}

struct osmo_pcap_client_conn *osmo_client_find_conn(
				struct osmo_pcap_client *client,
				const char *name)
{
	struct osmo_pcap_client_conn *conn;

	llist_for_each_entry(conn, &client->conns, entry)
		if (strcmp(conn->name, name) == 0)
			return conn;

	return NULL;
}

struct osmo_pcap_client_conn *osmo_client_conn_alloc(
				struct osmo_pcap_client *client,
				const char *name)
{
	struct osmo_pcap_client_conn *conn;

	conn = talloc_zero(client, struct osmo_pcap_client_conn);
	OSMO_ASSERT(conn);

	conn->name = talloc_strdup(conn, name);
	OSMO_ASSERT(conn->name);

	conn->client = client;
	conn->tls_verify = true;
	osmo_wqueue_init(&conn->wqueue, WQUEUE_MAXLEN_DEFAULT);
	conn->wqueue.bfd.fd = -1;

	llist_add_tail(&conn->entry, &client->conns);
	return conn;
}

struct osmo_pcap_client_conn *osmo_client_find_or_create_conn(
				struct osmo_pcap_client *client,
				const char *name)
{
	struct osmo_pcap_client_conn *conn;

	conn = osmo_client_find_conn(client, name);
	if (!conn)
		conn = osmo_client_conn_alloc(client, name);
	return conn;
}

struct osmo_pcap_handle *osmo_client_find_handle(struct osmo_pcap_client *client, const char *devname)
{
	struct osmo_pcap_handle *ph;

	llist_for_each_entry(ph, &client->handles, entry)
		if (strcmp(ph->devname, devname) == 0)
			return ph;
	return NULL;
}

struct osmo_pcap_handle *osmo_pcap_handle_alloc(struct osmo_pcap_client *client, const char *devname)
{
	struct osmo_pcap_handle *ph;

	ph = talloc_zero(client, struct osmo_pcap_handle);
	OSMO_ASSERT(ph);

	ph->devname = talloc_strdup(ph, devname);
	OSMO_ASSERT(ph->devname);

	ph->client = client;
	ph->idx = client->next_pcap_handle_idx++;
	ph->fd.fd = -1;

	/* initialize the stats interface */
	ph->ctrg = rate_ctr_group_alloc(ph, &pcap_handle_ctr_group_desc, ph->idx);
	OSMO_ASSERT(ph->ctrg);
	rate_ctr_group_set_name(ph->ctrg, ph->devname);

	llist_add_tail(&ph->entry, &client->handles);
	return ph;
}

void osmo_pcap_handle_free(struct osmo_pcap_handle *ph)
{
	if (!ph)
		return;
	llist_del(&ph->entry);

	osmo_timer_del(&ph->pcap_stat_timer);

	pcap_freecode(&ph->bpf);

	if (ph->fd.fd >= 0) {
		osmo_fd_unregister(&ph->fd);
		ph->fd.fd = -1;
	}

	if (ph->handle) {
		pcap_close(ph->handle);
		ph->handle = NULL;
	}

	rate_ctr_group_free(ph->ctrg);
	ph->ctrg = NULL;

	talloc_free(ph);
}

int osmo_pcap_handle_start_capture(struct osmo_pcap_handle *ph)
{
	struct osmo_pcap_client *client = ph->client;
	int fd;
	char errbuf[PCAP_ERRBUF_SIZE];

	LOGPH(ph, LOGL_INFO, "Opening device for capture with snaplen %zu\n", (size_t) client->snaplen);
	ph->handle = pcap_open_live(ph->devname, client->snaplen, 0, 1000, errbuf);
	if (!ph->handle) {
		LOGPH(ph, LOGL_ERROR, "Failed to open the device: %s\n", errbuf);
		return -2;
	}

	fd = pcap_fileno(ph->handle);
	if (fd == -1) {
		LOGPH(ph, LOGL_ERROR, "No file descriptor provided.\n");
		return -3;
	}

	osmo_fd_setup(&ph->fd, fd, OSMO_FD_READ, pcap_read_cb, ph, 0);
	if (osmo_fd_register(&ph->fd) != 0) {
		LOGPH(ph, LOGL_ERROR, "Failed to register the fd.\n");
		return -4;
	}

	osmo_timer_setup(&ph->pcap_stat_timer, pcap_check_stats_cb, ph);
	pcap_check_stats_cb(ph);

	if (client->filter_string)
		osmo_pcap_handle_install_filter(ph);
	return 0;
}
