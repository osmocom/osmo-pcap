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

#include <osmo-pcap/osmo_pcap_client.h>
#include <osmo-pcap/common.h>
#include <osmo-pcap/wireformat.h>

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

static void _osmo_client_connect(void *_data)
{
	osmo_client_connect((struct osmo_pcap_client_conn *) _data);
}

static void lost_connection(struct osmo_pcap_client_conn *conn)
{
	osmo_client_disconnect(conn);

	conn->timer.cb = _osmo_client_connect;
	conn->timer.data = conn;
	osmo_timer_schedule(&conn->timer, 2, 0);
}

static void write_data(struct osmo_pcap_client_conn *conn, struct msgb *msg)
{
	if (osmo_wqueue_enqueue_quiet(&conn->wqueue, msg) != 0) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to enqueue conn=%s\n", conn->name);
		rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_QERR]);
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
		LOGP(DCLIENT, LOGL_ERROR, "Lost connection on read conn=%s\n",
			conn->name);
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
		LOGP(DCLIENT, LOGL_ERROR, "Lost connection on write to %s %s:%d.\n",
			conn->name, conn->srv_ip, conn->srv_port);
		rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_WERR]);
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
	osmo_client_send_link(conn);
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
			osmo_client_send_link(conn);
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

void osmo_client_send_data(struct osmo_pcap_client_conn *conn,
			   struct pcap_pkthdr *in_hdr, const uint8_t *data)
{
	struct osmo_pcap_data *om_hdr;
	struct osmo_pcap_pkthdr *hdr;
	struct msgb *msg;
	int offset, ip_len;

	if (in_hdr->len > in_hdr->caplen) {
		LOGP(DCLIENT, LOGL_ERROR,
			"Recording truncated packet, len %zu > snaplen %zu\n",
			(size_t) in_hdr->len, (size_t) in_hdr->caplen);
		rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_2BIG]);
	}

	msg = msgb_alloc(in_hdr->caplen + sizeof(*om_hdr) + sizeof(*hdr), "data-data");
	if (!msg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate.\n");
		rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_NOMEM]);
		return;
	}

	switch (conn->protocol) {
	case PROTOCOL_OSMOPCAP:
		om_hdr = (struct osmo_pcap_data *) msgb_put(msg, sizeof(*om_hdr));
		om_hdr->type = PKT_LINK_DATA;

		msg->l2h = msgb_put(msg, sizeof(*hdr));
		hdr = (struct osmo_pcap_pkthdr *) msg->l2h;
		hdr->ts_sec = in_hdr->ts.tv_sec;
		hdr->ts_usec = in_hdr->ts.tv_usec;
		hdr->caplen = in_hdr->caplen;
		hdr->len = in_hdr->len;

		msg->l3h = msgb_put(msg, in_hdr->caplen);
		memcpy(msg->l3h, data, in_hdr->caplen);

		om_hdr->len = htons(msgb_l2len(msg));
		rate_ctr_add(&conn->client->ctrg->ctr[CLIENT_CTR_BYTES], hdr->caplen);
		rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_PKTS]);
		break;
	case PROTOCOL_IPIP:
		offset = get_iphdr_offset(pcap_datalink(conn->client->handle));
		if (offset < 0) {
			msgb_free(msg);
			return;
		}
		ip_len = in_hdr->caplen - offset;
		if (ip_len < 0) {
			msgb_free(msg);
			return;
		}
		msg->l2h = msgb_put(msg, ip_len);
		memcpy(msg->l2h, data+offset, ip_len);
		break;
	default:
		OSMO_ASSERT(0);
	}

	write_data(conn, msg);
}

void osmo_client_send_link(struct osmo_pcap_client_conn *conn)
{
	struct pcap_file_header *hdr;
	struct osmo_pcap_data *om_hdr;
	struct msgb *msg;

	/* IPIP encapsulation has no linktype header */
	if (conn->protocol == PROTOCOL_IPIP)
		return;

	if (!conn->client->handle) {
		LOGP(DCLIENT, LOGL_ERROR,
			"No pcap_handle not sending link info to conn=%s\n", conn->name);
		return;
	}

	msg = msgb_alloc(sizeof(*om_hdr) + sizeof(*hdr), "link-data");
	if (!msg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate data.\n");
		return;
	}


	om_hdr = (struct osmo_pcap_data *) msgb_put(msg, sizeof(*om_hdr));
	om_hdr->type = PKT_LINK_HDR;
	om_hdr->len = htons(sizeof(*hdr));

	hdr = (struct pcap_file_header *) msgb_put(msg, sizeof(*hdr));
	hdr->magic = 0xa1b2c3d4;
	hdr->version_major = 2;
	hdr->version_minor = 4;
	hdr->thiszone = 0;
	hdr->sigfigs = 0;
	hdr->snaplen = conn->client->snaplen;
	hdr->linktype = pcap_datalink(conn->client->handle);

	write_data(conn, msg);
}

void osmo_client_connect(struct osmo_pcap_client_conn *conn)
{
	int rc;
	uint16_t srv_port;
	int sock_type, sock_proto;
	unsigned int when;

	osmo_client_disconnect(conn);

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
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to connect conn=%s to %s:%d\n",
		     conn->name, conn->srv_ip, conn->srv_port);
		lost_connection(conn);
		return;
	}
	osmo_fd_setup(&conn->wqueue.bfd, rc, when, conn_cb, conn, 0);
	osmo_fd_register(&conn->wqueue.bfd);

	rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_CONNECT]);
}

void osmo_client_reconnect(struct osmo_pcap_client_conn *conn)
{
	lost_connection(conn);
}

void osmo_client_disconnect(struct osmo_pcap_client_conn *conn)
{
	if (conn->wqueue.bfd.fd >= 0) {
		osmo_tls_release(&conn->tls_session);
		osmo_fd_unregister(&conn->wqueue.bfd);
		close(conn->wqueue.bfd.fd);
		conn->wqueue.bfd.fd = -1;
	}

	osmo_timer_del(&conn->timer);
}
