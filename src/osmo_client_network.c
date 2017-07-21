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
	if (osmo_wqueue_enqueue(&conn->wqueue, msg) != 0) {
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
	if (what & BSC_FD_WRITE) {
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

	if (what & BSC_FD_READ)
		read_cb(fd);
	return 0;
}

void osmo_client_send_data(struct osmo_pcap_client_conn *conn,
			   struct pcap_pkthdr *in_hdr, const uint8_t *data)
{
	struct osmo_pcap_data *om_hdr;
	struct osmo_pcap_pkthdr *hdr;
	struct msgb *msg;

	if (in_hdr->caplen > 9000) {
		LOGP(DCLIENT, LOGL_ERROR,
			"Capture len too big %zu\n", in_hdr->caplen);
		rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_2BIG]);
		return;
	}

	msg = msgb_alloc(9000 + sizeof(*om_hdr) + sizeof(*hdr), "data-data");
	if (!msg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate.\n");
		rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_NOMEM]);
		return;
	}

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

	write_data(conn, msg);
}

void osmo_client_send_link(struct osmo_pcap_client_conn *conn)
{
	struct pcap_file_header *hdr;
	struct osmo_pcap_data *om_hdr;
	struct msgb *msg;

	if (!conn->client->handle) {
		LOGP(DCLIENT, LOGL_ERROR,
			"No pcap_handle not sending link info to conn=%s\n", conn->name);
		return;
	}

	msg = msgb_alloc(9000 + sizeof(*om_hdr) + sizeof(*hdr), "link-data");
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
	hdr->snaplen = UINT_MAX;
	hdr->linktype = pcap_datalink(conn->client->handle);

	write_data(conn, msg);
}

void osmo_client_connect(struct osmo_pcap_client_conn *conn)
{
	int fd;

	osmo_client_disconnect(conn);

	conn->wqueue.read_cb = read_cb;
	conn->wqueue.write_cb = write_cb;
	conn->wqueue.bfd.when = BSC_FD_READ;
	osmo_wqueue_clear(&conn->wqueue);

	fd = osmo_sock_init2(AF_INET, SOCK_STREAM, IPPROTO_TCP,
				conn->source_ip, 0,
				conn->srv_ip, conn->srv_port,
				OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_NONBLOCK);
	if (fd < 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to connect conn=%s to %s:%d\n",
		     conn->name, conn->srv_ip, conn->srv_port);
		lost_connection(conn);
		return;
	}

	conn->wqueue.bfd.fd = fd;
	if (osmo_fd_register(&conn->wqueue.bfd) != 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to register to BFD conn=%s\n", conn->name);
		lost_connection(conn);
		return;
	}

	rate_ctr_inc(&conn->client->ctrg->ctr[CLIENT_CTR_CONNECT]);
	conn->wqueue.bfd.cb = conn_cb;
	conn->wqueue.bfd.data = conn;
	conn->wqueue.bfd.when = BSC_FD_READ | BSC_FD_WRITE;
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
