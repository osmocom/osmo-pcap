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

#include <osmo-pcap/osmo_pcap_client.h>
#include <osmo-pcap/common.h>
#include <osmo-pcap/wireformat.h>
#include <osmo-pcap/osmo_pcap_file.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

static void _osmo_client_conn_connect(void *_data)
{
	osmo_client_conn_connect((struct osmo_pcap_client_conn *) _data);
}

static void lost_connection(struct osmo_pcap_client_conn *conn)
{
	osmo_client_conn_disconnect(conn);

	conn->timer.cb = _osmo_client_conn_connect;
	conn->timer.data = conn;
	osmo_timer_schedule(&conn->timer, 2, 0);
}

static void write_data(struct osmo_pcap_client_conn *conn, struct msgb *msg)
{
	if (osmo_wqueue_enqueue_quiet(&conn->wqueue, msg) != 0) {
		LOGCONN(conn, LOGL_ERROR, "Failed to enqueue msg (capacity: %u/%u)\n",
			conn->wqueue.current_length, conn->wqueue.max_length);
		rate_ctr_inc2(conn->client->ctrg, CLIENT_CTR_QERR);
		msgb_free(msg);
		return;
	}
}

static int read_cb(struct osmo_fd *fd)
{
	char buf[4096];
	int rc;

	rc = read(fd->fd, buf, sizeof(buf));
	if (rc <= 0) {
		struct osmo_pcap_client_conn *conn = fd->data;
		LOGCONN(conn, LOGL_ERROR, "Lost connection on read\n");
		lost_connection(conn);
		return -1;
	}

	return 0;
}

static int write_cb(struct osmo_fd *fd, struct msgb *msg)
{
	int rc;

	rc = write(fd->fd, msg->data, msg->len);
	if (rc < 0) {
		struct osmo_pcap_client_conn *conn = fd->data;
		LOGCONN(conn, LOGL_ERROR, "Lost connection on write\n");
		rate_ctr_inc2(conn->client->ctrg, CLIENT_CTR_WERR);
		lost_connection(conn);
		return -1;
	}

	return 0;
}

static void handshake_done_cb(struct osmo_tls_session *session)
{
	struct osmo_pcap_client_conn *conn;

	conn = container_of(session, struct osmo_pcap_client_conn, tls_session);
	osmo_wqueue_clear(&conn->wqueue);
	osmo_client_conn_send_link(conn);
}

static void tls_error_cb(struct osmo_tls_session *session)
{
	struct osmo_pcap_client_conn *conn;

	conn = container_of(session, struct osmo_pcap_client_conn, tls_session);
	lost_connection(conn);
}

int conn_cb(struct osmo_fd *fd, unsigned int what)
{
	/* finally the socket is connected... continue */
	if (what & OSMO_FD_WRITE) {
		struct osmo_pcap_client_conn *conn = fd->data;
		/*
		 * The write queue needs to work differently for GNUtls. Before we can
		 * send data we will need to complete handshake.
		 */
		if (conn->tls_on) {
			if (!osmo_tls_init_client_session(conn)) {
				lost_connection(conn);
				return -1;
			}
			conn->tls_session.handshake_done = handshake_done_cb;
			conn->tls_session.error = tls_error_cb;

			/* fd->data now points somewhere else, stop */
			return 0;
		} else {
			conn->wqueue.bfd.cb = osmo_wqueue_bfd_cb;
			conn->wqueue.bfd.data = conn;
			osmo_wqueue_clear(&conn->wqueue);
			osmo_client_conn_send_link(conn);
		}
	}

	if (what & OSMO_FD_READ)
		read_cb(fd);
	return 0;
}

static int get_iphdr_offset(int dlt)
{
	switch (dlt) {
	case DLT_EN10MB:
		return 14;
	case DLT_LINUX_SLL:
		return 16;
	default:
		return -1;
	}
}

static struct msgb *osmo_client_conn_prepare_msg_data_pcap(struct osmo_pcap_client_conn *conn,
							   const struct osmo_pcap_handle *ph,
							   const struct pcap_pkthdr *pkthdr,
							   const uint8_t *data)
{
	struct osmo_pcap_data *om_hdr;
	struct msgb *msg;
	unsigned int record_size = osmo_pcap_file_record_size(pkthdr);

	msg = msgb_alloc(sizeof(*om_hdr) + record_size, "pcap-data");
	if (!msg) {
		LOGCONN(conn, LOGL_ERROR, "Failed to allocate\n");
		rate_ctr_inc2(conn->client->ctrg, CLIENT_CTR_NOMEM);
		return NULL;
	}

	om_hdr = (struct osmo_pcap_data *) msgb_put(msg, sizeof(*om_hdr));
	om_hdr->type = PKT_LINK_DATA;
	om_hdr->len = htons(record_size);
	osmo_pcap_file_msgb_append_record(msg, pkthdr, data);

	return msg;
}

static struct msgb *osmo_client_conn_prepare_msg_data_pcapng(struct osmo_pcap_client_conn *conn,
							     const struct osmo_pcap_handle *ph,
							     const struct pcap_pkthdr *pkthdr,
							     const uint8_t *data)
{
	struct osmo_pcap_data *om_hdr;
	struct msgb *msg;
	struct osmo_pcapng_file_epb_pars epb_pars;
	unsigned int record_size;
	int rc;

	epb_pars = (struct osmo_pcapng_file_epb_pars){
		.timestamp_usec = (pkthdr->ts.tv_sec * 1000 * 1000) + pkthdr->ts.tv_usec,
		.interface_id = ph->idx,
		.captured_data = data,
		.captured_len = pkthdr->caplen,
		.packet_len = pkthdr->len,
	};

	record_size = osmo_pcapng_file_epb_size(&epb_pars);

	msg = msgb_alloc(sizeof(*om_hdr) + record_size, "pcap-data");
	if (!msg) {
		LOGCONN(conn, LOGL_ERROR, "Failed to allocate\n");
		rate_ctr_inc2(conn->client->ctrg, CLIENT_CTR_NOMEM);
		return NULL;
	}

	om_hdr = (struct osmo_pcap_data *) msgb_put(msg, sizeof(*om_hdr));
	om_hdr->type = PKT_LINK_DATA;
	om_hdr->len = htons(record_size);
	rc = osmo_pcapng_file_msgb_append_epb(msg, &epb_pars);
	if (rc < 0) {
		msgb_free(msg);
		return NULL;
	}

	return msg;
}

static struct msgb *osmo_client_conn_prepare_msg_ipip(struct osmo_pcap_client_conn *conn,
						      const struct osmo_pcap_handle *ph,
						      const struct pcap_pkthdr *pkthdr,
						      const uint8_t *data)
{
	struct msgb *msg;
	int offset, ip_len;

	offset = get_iphdr_offset(pcap_datalink(ph->handle));
	if (offset < 0)
		return NULL;

	ip_len = pkthdr->caplen - offset;
	if (ip_len < 0)
		return NULL;


	msg = msgb_alloc(ip_len, "ipip_msg");
	if (!msg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate data.\n");
		rate_ctr_inc2(conn->client->ctrg, CLIENT_CTR_NOMEM);
		return NULL;
	}
	msg->l2h = msgb_put(msg, ip_len);
	memcpy(msg->l2h, data+offset, ip_len);
	return msg;
}

void osmo_client_conn_send_data(struct osmo_pcap_client_conn *conn,
				const struct osmo_pcap_handle *ph,
				const struct pcap_pkthdr *pkthdr,
				const uint8_t *data)
{
	struct osmo_pcap_client *client = conn->client;
	struct msgb *msg;

	if (pkthdr->len > pkthdr->caplen) {
		LOGCONN(conn, LOGL_ERROR, "Recording truncated packet, len %zu > snaplen %zu\n",
			(size_t) pkthdr->len, (size_t) pkthdr->caplen);
		rate_ctr_inc2(client->ctrg, CLIENT_CTR_2BIG);
	}

	switch (conn->protocol) {
	case PROTOCOL_OSMOPCAP:
		switch (client->pcap_fmt) {
		case OSMO_PCAP_FMT_PCAP:
			msg = osmo_client_conn_prepare_msg_data_pcap(conn, ph, pkthdr, data);
			break;
		case OSMO_PCAP_FMT_PCAPNG:
			msg = osmo_client_conn_prepare_msg_data_pcapng(conn, ph, pkthdr, data);
			break;
		default:
			OSMO_ASSERT(0);
		}
		break;
	case PROTOCOL_IPIP:
		msg = osmo_client_conn_prepare_msg_ipip(conn, ph, pkthdr, data);
		break;
	default:
		OSMO_ASSERT(0);
	}

	if (!msg)
		return;

	rate_ctr_add2(conn->client->ctrg, CLIENT_CTR_BYTES, pkthdr->caplen);
	rate_ctr_inc2(conn->client->ctrg, CLIENT_CTR_PKTS);

	write_data(conn, msg);
}

static struct msgb *osmo_client_conn_prepare_msg_link_pcap(struct osmo_pcap_client_conn *conn)
{
	struct osmo_pcap_client *client = conn->client;
	struct osmo_pcap_data *om_hdr;
	struct msgb *msg;
	struct osmo_pcap_handle *ph;
	int rc;
	int linktype;

	ph = llist_first_entry_or_null(&client->handles, struct osmo_pcap_handle, entry);
	if (!ph || !ph->handle) {
		LOGCONN(conn, LOGL_ERROR, "No pcap_handle not sending link info\n");
		return NULL;
	}
	linktype = pcap_datalink(ph->handle);

	/* Make sure others have same linktype, .pcap doesn't support different
	 * linktypes since traffic from all ifaces goes mixed together. */
	llist_for_each_entry(ph, &client->handles, entry) {
		if (linktype != pcap_datalink(ph->handle)) {
			LOGCONN(conn, LOGL_ERROR,
				"File format 'pcap' doesn't support recording from multiple ifaces "
				"with different link types! Use VTY config 'pcap file-format pcapng'.\n");
			return NULL;
		}
	}

	msg = msgb_alloc(sizeof(*om_hdr) + sizeof(struct pcap_file_header), "link-data");
	if (!msg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate data.\n");
		return NULL;
	}


	om_hdr = (struct osmo_pcap_data *)msgb_put(msg, sizeof(*om_hdr));
	om_hdr->type = PKT_LINK_HDR;

	rc = osmo_pcap_file_msgb_append_global_header(msg, client->snaplen, linktype);
	if (rc < 0) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to create pcap file global header.\n");
		msgb_free(msg);
		return NULL;
	}

	/* Update payload length: */
	om_hdr->len = htons(rc);
	return msg;
}

struct osmo_pcapng_file_shb_pars shb_pars = {
	.hardware = "osmo-pcap hw",
	.os = "osmo-pcap os",
	.userappl = "osmo-pcap userappl",
};

static int pcap_handle_prepare_pcapng_idb_pars(const struct osmo_pcap_handle *ph,
					       struct osmo_pcapng_file_idb_pars *pars)
{
	struct osmo_pcap_client *client = ph->client;
	memset(pars, 0, sizeof(*pars));

	pars->name = ph->devname;
	pars->filter = client->filter_string;
	pars->link_type = pcap_datalink(ph->handle);
	pars->snap_len = client->snaplen;
	return 0;
}

static struct msgb *osmo_client_conn_prepare_msg_link_pcapng(struct osmo_pcap_client_conn *conn)
{
	struct osmo_pcap_data *om_hdr;
	struct msgb *msg;
	struct osmo_pcap_handle *ph;
	int rc;
	uint32_t file_hdr_size = osmo_pcapng_file_shb_size(&shb_pars);

	/* Calculate size: */
	llist_for_each_entry(ph, &conn->client->handles, entry) {
		struct osmo_pcapng_file_idb_pars idb_pars;
		if (pcap_handle_prepare_pcapng_idb_pars(ph, &idb_pars) < 0) {
			LOGPH(ph, LOGL_ERROR, "Failed preparing pcapng IDB from handle\n");
			return NULL;
		}
		file_hdr_size += osmo_pcapng_file_idb_size(&idb_pars);
	}

	msg = msgb_alloc(sizeof(*om_hdr) + file_hdr_size, "link-data");
	if (!msg) {
		LOGCONN(conn, LOGL_ERROR, "Failed to allocate data\n");
		return NULL;
	}

	om_hdr = (struct osmo_pcap_data *)msgb_put(msg, sizeof(*om_hdr));
	om_hdr->type = PKT_LINK_HDR;

	rc = osmo_pcapng_file_msgb_append_shb(msg, &shb_pars);
	if (rc < 0) {
		LOGCONN(conn, LOGL_ERROR, "Failed to create pcapng SHB\n");
		msgb_free(msg);
		return NULL;
	}
	om_hdr->len = rc;

	llist_for_each_entry(ph, &conn->client->handles, entry) {
		struct osmo_pcapng_file_idb_pars idb_pars;
		if (pcap_handle_prepare_pcapng_idb_pars(ph, &idb_pars) < 0) {
			LOGPH(ph, LOGL_ERROR, "Failed preparing pcapng IDB from handle\n");
			msgb_free(msg);
			return NULL;
		}
		rc = osmo_pcapng_file_msgb_append_idb(msg, &idb_pars);
		if (rc < 0) {
			LOGPH(ph, LOGL_ERROR, "Failed to append pcapng IDB to msgb\n");
			msgb_free(msg);
			return NULL;
		}
		om_hdr->len += rc;
	}

	OSMO_ASSERT(om_hdr->len == file_hdr_size);
	om_hdr->len = htons(om_hdr->len);
	return msg;
}

void osmo_client_conn_send_link(struct osmo_pcap_client_conn *conn)
{
	struct msgb *msg;

	/* IPIP encapsulation has no linktype header */
	if (conn->protocol == PROTOCOL_IPIP)
		return;

	switch (conn->client->pcap_fmt) {
	case OSMO_PCAP_FMT_PCAP:
		msg = osmo_client_conn_prepare_msg_link_pcap(conn);
		break;
	case OSMO_PCAP_FMT_PCAPNG:
		msg = osmo_client_conn_prepare_msg_link_pcapng(conn);
		break;
	default:
		OSMO_ASSERT(0);
	}

	if (!msg)
		return;
	write_data(conn, msg);
}

void osmo_client_conn_connect(struct osmo_pcap_client_conn *conn)
{
	int rc;
	uint16_t srv_port;
	int sock_type, sock_proto;
	unsigned int when;

	osmo_client_conn_disconnect(conn);

	conn->wqueue.read_cb = read_cb;
	conn->wqueue.write_cb = write_cb;
	osmo_wqueue_clear(&conn->wqueue);

	switch (conn->protocol) {
	case PROTOCOL_OSMOPCAP:
		srv_port = conn->srv_port;
		sock_type = SOCK_STREAM;
		sock_proto = IPPROTO_TCP;
		when = OSMO_FD_READ | OSMO_FD_WRITE;
		break;
	case PROTOCOL_IPIP:
		srv_port = 0;
		sock_type = SOCK_RAW;
		sock_proto = IPPROTO_IPIP;
		when = OSMO_FD_WRITE;
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}

	rc = osmo_sock_init2(AF_INET, sock_type, sock_proto, conn->source_ip, 0, conn->srv_ip, srv_port,
			     OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_NONBLOCK);
	if (rc < 0) {
		LOGCONN(conn, LOGL_ERROR, "Failed to connect\n");
		lost_connection(conn);
		return;
	}
	osmo_fd_setup(&conn->wqueue.bfd, rc, when, conn_cb, conn, 0);
	osmo_fd_register(&conn->wqueue.bfd);

	rate_ctr_inc2(conn->client->ctrg, CLIENT_CTR_CONNECT);
}

void osmo_client_conn_reconnect(struct osmo_pcap_client_conn *conn)
{
	lost_connection(conn);
}

void osmo_client_conn_disconnect(struct osmo_pcap_client_conn *conn)
{
	if (conn->wqueue.bfd.fd >= 0) {
		osmo_tls_release(&conn->tls_session);
		osmo_fd_unregister(&conn->wqueue.bfd);
		close(conn->wqueue.bfd.fd);
		conn->wqueue.bfd.fd = -1;
	}

	osmo_timer_del(&conn->timer);
}
