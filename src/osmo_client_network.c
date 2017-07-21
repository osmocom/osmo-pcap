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


/*
 * Move to libosmocore... if the api makes source
 */
static int sock_src_init(uint16_t family, uint16_t type, uint8_t proto,
		   const char *src, uint16_t src_port,
		   const char *host, uint16_t port, unsigned int flags)
{
	struct addrinfo hints, *result, *rp;
	struct addrinfo *src_result, *src_rp = NULL;
	int sfd, rc, on = 1;
	char portbuf[16];
	char src_portbuf[16];

	sprintf(portbuf, "%u", port);
	sprintf(src_portbuf, "%u", src_port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family;
	if (type == SOCK_RAW) {
		/* Workaround for glibc, that returns EAI_SERVICE (-8) if
		 * SOCK_RAW and IPPROTO_GRE is used.
		 */
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = type;
		hints.ai_protocol = proto;
	}

	rc = getaddrinfo(host, portbuf, &hints, &result);
	if (rc != 0) {
		fprintf(stderr, "getaddrinfo returned NULL: %s:%u: %s\n",
			host, port, strerror(errno));
		return -EINVAL;
	}

	if (src) {
		rc = getaddrinfo(src, src_portbuf, &hints, &src_result);
		if (rc != 0) {
			fprintf(stderr, "getaddrinfo returned NULL: %s:%u: %s\n",
				src, src_port, strerror(errno));
			freeaddrinfo(result);
			return -EINVAL;
		}

		/* select an address */
		for (src_rp = src_result; src_rp != NULL; src_rp = src_rp->ai_next) {
			/* Workaround for glibc again */
			if (type == SOCK_RAW) {
				src_rp->ai_socktype = SOCK_RAW;
				src_rp->ai_protocol = proto;
			}
			break;
		}

		if (!src_rp) {
			fprintf(stderr, "Failed to get src: %s:%u %s\n",
				src, src_port, strerror(errno));
			freeaddrinfo(result);
			freeaddrinfo(src_result);
			return -EINVAL;
		}
	}


	for (rp = result; rp != NULL; rp = rp->ai_next) {
		/* Workaround for glibc again */
		if (type == SOCK_RAW) {
			rp->ai_socktype = SOCK_RAW;
			rp->ai_protocol = proto;
		}

		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;
		if (flags & OSMO_SOCK_F_NONBLOCK) {
			if (ioctl(sfd, FIONBIO, (unsigned char *)&on) < 0) {
				fprintf(stderr,
					"cannot set this socket unblocking:"
					" %s:%u: %s\n",
					host, port, strerror(errno));
				close(sfd);
				freeaddrinfo(result);
				return -EINVAL;
			}
		}


		if (src_rp) {
			rc = bind(sfd, src_rp->ai_addr, src_rp->ai_addrlen);
			if (rc != 0) {
				fprintf(stderr,
					"cannot bind socket:"
					" %s:%u: %s\n",
					src, src_port, strerror(errno));
				close(sfd);
				continue;
			}
		}

		if (flags & OSMO_SOCK_F_CONNECT) {
			rc = connect(sfd, rp->ai_addr, rp->ai_addrlen);
			if (rc != -1 || (rc == -1 && errno == EINPROGRESS))
				break;
		} else {
			rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
							&on, sizeof(on));
			if (rc < 0) {
				fprintf(stderr,
					"cannot setsockopt socket:"
					" %s:%u: %s\n",
					host, port, strerror(errno));
				break;
			}
			if (bind(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
				break;
		}
		close(sfd);
	}
	freeaddrinfo(result);
	if (src)
		freeaddrinfo(src_result);

	if (rp == NULL) {
		fprintf(stderr, "unable to connect/bind socket: %s:%u: %s\n",
			host, port, strerror(errno));
		return -ENODEV;
	}

	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	return sfd;
}

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

	fd = sock_src_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
				conn->source_ip, 0,
				conn->srv_ip, conn->srv_port,
				OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_NONBLOCK);
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
