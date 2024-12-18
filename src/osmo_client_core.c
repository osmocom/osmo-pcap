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

	ll_type = pcap_datalink(client->handle);
	switch (ll_type) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_LINUX_SLL:
		offset = 16;
		break;
	default:
		LOGP(DCLIENT, LOGL_ERROR, "LL type %d/%s not handled.\n",
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
	struct osmo_pcap_client *client = fd->data;
	struct osmo_pcap_client_conn *conn;
	struct pcap_pkthdr hdr;
	const u_char *data;

	data = pcap_next(client->handle, &hdr);
	if (!data) {
		rate_ctr_inc(rate_ctr_group_get_ctr(client->ctrg, CLIENT_CTR_PERR));
		return -1;
	}

	if (!can_forward_packet(client, &hdr, data))
		return 0;

	llist_for_each_entry(conn, &client->conns, entry)
		osmo_client_send_data(conn, &hdr, data);
	return 0;
}

static inline u_int P_CAP_UINT_MAX()
{
	u_int val = 0;
	return ~val;
}

static void add_psbl_wrapped_ctr(struct osmo_pcap_client *client,
				u_int *old_val, u_int new_val, int ctr)
{
	/*
	 * Wrapped..
	 * So let's at from N to XYZ_MAX
	 * and then from 0 to new_val
	 * Only issue is we don't know sizeof(u_int)
	 */
	if (*old_val > new_val) {
		rate_ctr_add(rate_ctr_group_get_ctr(client->ctrg, ctr), P_CAP_UINT_MAX() - *old_val);
		rate_ctr_add(rate_ctr_group_get_ctr(client->ctrg, ctr), new_val);
		*old_val = new_val;
		return;
	}

	/* Just increment it */
	rate_ctr_add(rate_ctr_group_get_ctr(client->ctrg, ctr), new_val - *old_val);
	*old_val = new_val;
}

static void pcap_check_stats_cb(void *_client)
{
	struct pcap_stat stat;
	struct osmo_pcap_client *client = _client;
	int rc;

	/* reschedule */
	osmo_timer_schedule(&client->pcap_stat_timer, 10, 0);

	memset(&stat, 0, sizeof(stat));
	rc = pcap_stats(client->handle, &stat);
	if (rc != 0) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to query pcap stats: %s\n",
			pcap_geterr(client->handle));
		rate_ctr_inc(rate_ctr_group_get_ctr(client->ctrg, CLIENT_CTR_PERR));
		return;
	}

	add_psbl_wrapped_ctr(client, &client->last_ps_recv, stat.ps_recv, CLIENT_CTR_P_RECV);
	add_psbl_wrapped_ctr(client, &client->last_ps_drop, stat.ps_drop, CLIENT_CTR_P_DROP);
	add_psbl_wrapped_ctr(client, &client->last_ps_ifdrop, stat.ps_ifdrop, CLIENT_CTR_P_IFDROP);
}

static int osmo_install_filter(struct osmo_pcap_client *client)
{
	int rc;
	pcap_freecode(&client->bpf);

	if (!client->handle) {
		LOGP(DCLIENT, LOGL_NOTICE,
		    "Filter will only be applied later.\n");
		return 1;
	}

	rc = pcap_compile(client->handle, &client->bpf,
			  client->filter_string, 1, PCAP_NETMASK_UNKNOWN);
	if (rc != 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to compile the filter: %s\n",
		     pcap_geterr(client->handle));
		return rc;
	}

	rc = pcap_setfilter(client->handle, &client->bpf);
	if (rc != 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to set the filter on the interface: %s\n",
		     pcap_geterr(client->handle));
		pcap_freecode(&client->bpf);
		return rc;
	}

	return rc;
}

static void free_all(struct osmo_pcap_client *client)
{
	if (!client->handle)
		return;

	pcap_freecode(&client->bpf);

	if (client->fd.fd >= 0) {
		osmo_fd_unregister(&client->fd);
		client->fd.fd = -1;
	}

	pcap_close(client->handle);
	osmo_timer_del(&client->pcap_stat_timer);
	client->handle = NULL;
}

int osmo_client_capture(struct osmo_pcap_client *client, const char *device)
{
	struct osmo_pcap_client_conn *conn;
	int fd;

	talloc_free(client->device);
	free_all(client);

	client->device = talloc_strdup(client, device);
	if (!client->device) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to copy string.\n");
		return 1;
	}

	LOGP(DCLIENT, LOGL_INFO, "Opening device %s for capture with snaplen %zu\n",
	     client->device, (size_t) client->snaplen);
	client->handle = pcap_open_live(client->device, client->snaplen, 0,
					1000, client->errbuf);
	if (!client->handle) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to open the device: %s\n", client->errbuf);
		return 2;
	}

	fd = pcap_fileno(client->handle);
	if (fd == -1) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "No file descriptor provided.\n");
		free_all(client);
		return 3;
	}

	osmo_fd_setup(&client->fd, fd, OSMO_FD_READ, pcap_read_cb, client, 0);
	if (osmo_fd_register(&client->fd) != 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to register the fd.\n");
		client->fd.fd = -1;
		free_all(client);
		return 4;
	}

	client->pcap_stat_timer.data = client;
	client->pcap_stat_timer.cb = pcap_check_stats_cb;
	pcap_check_stats_cb(client);

	llist_for_each_entry(conn, &client->conns, entry)
		osmo_client_send_link(conn);

	if (client->filter_string) {
		osmo_install_filter(client);
	}

	return 0;
}

int osmo_client_filter(struct osmo_pcap_client *client, const char *filter)
{
	talloc_free(client->filter_string);
	client->filter_string = talloc_strdup(client, filter);
	return osmo_install_filter(client);
}

struct osmo_pcap_client *osmo_pcap_client_alloc(void *tall_ctx)
{
	struct osmo_pcap_client *client;
	client = talloc_zero(tall_ctx, struct osmo_pcap_client);
	if (!client)
		return NULL;

	client->fd.fd = -1;
	client->snaplen = DEFAULT_SNAPLEN;
	INIT_LLIST_HEAD(&client->conns);

	return client;
}

void osmo_client_free(struct osmo_pcap_client_conn *conn)
{
	osmo_client_disconnect(conn);
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
