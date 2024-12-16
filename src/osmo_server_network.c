/*
 * osmo-pcap-server code
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

#include <osmo-pcap/osmo_pcap_server.h>
#include <osmo-pcap/common.h>
#include <osmo-pcap/wireformat.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <zmq.h>

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static void pcap_zmq_send(void *publ, const void *data, size_t len, int flags)
{
	int rc;
	zmq_msg_t msg;

	rc = zmq_msg_init_size(&msg, len);
	if (rc != 0) {
		/* sigh.. we said SNDMORE but can't... */
		LOGP(DSERVER, LOGL_ERROR, "Failed to init rc=%d errno=%d/%s\n",
			rc, errno, strerror(errno));
		return;
	}
	memcpy(zmq_msg_data(&msg), data, len);
	rc = zmq_msg_send(&msg, publ, flags);
	if (rc == -1) {
		/* is the zmq_msg now owned? leak??? */
		LOGP(DSERVER, LOGL_ERROR, "Failed to send data rc=%d errno=%d/%s\n",
			rc, errno, strerror(errno));
		return;
	}
}

static void client_event(struct osmo_pcap_conn *conn,
				const char *event, const char *data)
{
	char *event_name;

	if (!conn->server->zmq_publ)
		return;

	/*
	 * This multi-part support is insane... so if we lose the first
	 * or the last part of the multipart message stuff is going out
	 * of sync. *great* As we can't do anything about it right now
	 * just close the eyese and send it.
	 */
	event_name = talloc_asprintf(conn, "event.v1.%s.%s",
				event, conn->name);
	pcap_zmq_send(conn->server->zmq_publ,
			event_name, strlen(event_name),
			data ? ZMQ_SNDMORE : 0);
	talloc_free(event_name);
	if (data)
		pcap_zmq_send(conn->server->zmq_publ, data, strlen(data), 0);
}

static void client_data(struct osmo_pcap_conn *conn,
				struct osmo_pcap_data *data)
{
	char *event_name;

	if (!conn->server->zmq_publ)
		return;

	/*
	 * This multi-part support is insane... so if we lose the first
	 * or the last part of the multipart message stuff is going out
	 * of sync. *great* As we can't do anything about it right now
	 * just close the eyese and send it.
	 */
	event_name = talloc_asprintf(conn, "data.v1.%s", conn->name);
	pcap_zmq_send(conn->server->zmq_publ, event_name, strlen(event_name), ZMQ_SNDMORE);
	talloc_free(event_name);

	pcap_zmq_send(conn->server->zmq_publ,
			&conn->file_hdr, sizeof(conn->file_hdr),
			ZMQ_SNDMORE);
	pcap_zmq_send(conn->server->zmq_publ,
			&data->data[0], data->len,
			0);
}

void osmo_pcap_server_close_trace(struct osmo_pcap_conn *conn)
{
	if (conn->local_fd >= 0) {
		close(conn->local_fd);
		conn->local_fd = -1;
	}

	if (conn->curr_filename) {
		client_event(conn, "closingtracefile", conn->curr_filename);
		rate_ctr_inc(rate_ctr_group_get_ctr(conn->ctrg, PEER_CTR_PROTATE));
		rate_ctr_inc(rate_ctr_group_get_ctr(conn->server->ctrg, SERVER_CTR_PROTATE));
		talloc_free(conn->curr_filename);
		conn->curr_filename = NULL;
	}
}

static void close_connection(struct osmo_pcap_conn *conn)
{
	if (conn->rem_wq.bfd.fd >= 0) {
		osmo_fd_unregister(&conn->rem_wq.bfd);
		close(conn->rem_wq.bfd.fd);
		conn->rem_wq.bfd.fd = -1;
		osmo_tls_release(&conn->tls_session);
	}

	osmo_pcap_server_close_trace(conn);
	client_event(conn, "disconnect", NULL);
}

void osmo_pcap_server_close_conn(struct osmo_pcap_conn *conn)
{
	return close_connection(conn);
}

static void restart_pcap(struct osmo_pcap_conn *conn)
{
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	int rc;

	osmo_pcap_server_close_trace(conn);

	/* omit any storing/creation of the file */
	if (conn->no_store) {
		conn->last_write = *tm;
		talloc_free(conn->curr_filename);
		conn->curr_filename = NULL;
		return;
	}

	conn->curr_filename = talloc_asprintf(conn, "%s/trace-%s-%d%.2d%.2d_%.2d%.2d%.2d.pcap",
				   conn->server->base_path, conn->name,
				   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				   tm->tm_hour, tm->tm_min, tm->tm_sec);

	if (!conn->curr_filename) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to assemble filename for %s.\n", conn->name);
		return;
	}

	conn->local_fd = creat(conn->curr_filename, conn->server->permission_mask);
	if (conn->local_fd < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to file: '%s'\n", conn->curr_filename);
		return;
	}

	rc = write(conn->local_fd, &conn->file_hdr, sizeof(conn->file_hdr));
	if (rc != sizeof(conn->file_hdr)) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to write the header: %d\n", errno);
		close(conn->local_fd);
		conn->local_fd = -1;
		return;
	}

	conn->last_write = *tm;
}

static int link_data(struct osmo_pcap_conn *conn, struct osmo_pcap_data *data)
{
	struct pcap_file_header *hdr;

	hdr = (struct pcap_file_header *) &data->data[0];

	if (hdr->snaplen > conn->server->max_snaplen) {
		LOGP(DSERVER, LOGL_ERROR,
		     "The recvd pcap_file_header contains too big snaplen %zu > %zu\n",
		     (size_t) hdr->snaplen, (size_t) conn->server->max_snaplen);
		return -1;
	}

	if (!conn->no_store && conn->local_fd < 0) {
		conn->file_hdr = *hdr;
		restart_pcap(conn);
	} else if (memcmp(&conn->file_hdr, hdr, sizeof(*hdr)) != 0) {
		conn->file_hdr = *hdr;
		restart_pcap(conn);
	}

	return 1;
}

/* Returns true if pcap was re-opened */
static bool check_restart_pcap_max_size(struct osmo_pcap_conn *conn, const struct osmo_pcap_data *data)
{
	off_t cur;

	if (pcap_server->max_size_enabled)
		return false;
	cur = lseek(conn->local_fd, 0, SEEK_CUR);
	if (cur + data->len <= conn->server->max_size)
		return false;
	LOGP(DSERVER, LOGL_NOTICE, "Rolling over file for %s (max-size)\n", conn->name);
	restart_pcap(conn);
	return true;
}

static bool check_restart_pcap_localtime(struct osmo_pcap_conn *conn, const struct tm *tm)
{
	if (conn->last_write.tm_mday == tm->tm_mday &&
	    conn->last_write.tm_mon == tm->tm_mon &&
	    conn->last_write.tm_year == tm->tm_year)
		return false;
	LOGP(DSERVER, LOGL_NOTICE, "Rolling over file for %s (localtime)\n", conn->name);
	restart_pcap(conn);
	return true;
}

/*
 * Check if we are past the limit or on a day change
 */
static int write_data(struct osmo_pcap_conn *conn, struct osmo_pcap_data *data)
{
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	int rc;

	client_data(conn, data);

	if (conn->no_store) {
		conn->last_write = *tm;
		return 1;
	}

	if (conn->local_fd < -1) {
		LOGP(DSERVER, LOGL_ERROR, "No file is open. close connection.\n");
		return -1;
	}

	if (!check_restart_pcap_max_size(conn, data))
		check_restart_pcap_localtime(conn, tm);

	conn->last_write = *tm;
	rc = write(conn->local_fd, &data->data[0], data->len);
	if (rc != data->len) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to write for %s\n", conn->name);
		return -1;
	}
	return 1;
}


void osmo_pcap_server_delete(struct osmo_pcap_conn *conn)
{
	close_connection(conn);
	llist_del(&conn->entry);
	talloc_free(conn);
}

struct osmo_pcap_conn *osmo_pcap_server_find(struct osmo_pcap_server *server,
					     const char *name)
{
	struct rate_ctr_group_desc *desc;
	struct osmo_pcap_conn *conn;
	size_t buf_size;

	llist_for_each_entry(conn, &server->conn, entry) {
		if (strcmp(conn->name, name) == 0)
			return conn;
	}

	conn = talloc_zero(server, struct osmo_pcap_conn);
	if (!conn) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Failed to allocate the connection peer=%s.\n", name);
		return NULL;
	}

	buf_size = sizeof(struct osmo_pcap_data);
	buf_size += OSMO_MAX(sizeof(struct pcap_file_header),
			     sizeof(struct osmo_pcap_pkthdr) + server->max_snaplen);
	conn->data = talloc_zero_size(conn, buf_size);
	/* a bit nasty. we do not work with ids but names */
	desc = talloc_zero(conn, struct rate_ctr_group_desc);
	if (!desc) {
		LOGP(DSERVER, LOGL_ERROR,
			"Failed to allocate rate ctr desc peer=%s\n", name);
		talloc_free(conn);
		return NULL;
	}
	memcpy(desc, &pcap_peer_group_desc, sizeof(pcap_peer_group_desc));
	desc->group_name_prefix = talloc_asprintf(desc, "pcap:peer:%s", name);
	if (!desc->group_name_prefix) {
		LOGP(DSERVER, LOGL_ERROR,
			"Failed to allocate group name prefix peer=%s\n", name);
		talloc_free(conn);
		return NULL;
	}
	desc->group_description = talloc_asprintf(desc, "PCAP peer statistics %s", name);
	if (!desc->group_description) {
		LOGP(DSERVER, LOGL_ERROR,
			"Failed to allocate group description peer=%s\n", name);
		talloc_free(conn);
		return NULL;
	}

	conn->ctrg = rate_ctr_group_alloc(desc, desc, 0);
	if (!conn->ctrg) {
		LOGP(DSERVER, LOGL_ERROR,
			"Failed to allocate rate ctr peer=%s\n", name);
		talloc_free(conn);
		return NULL;
	}


	conn->name = talloc_strdup(conn, name);
	/* we never write */
	osmo_wqueue_init(&conn->rem_wq, 0);
	conn->rem_wq.bfd.fd = -1;
	conn->local_fd = -1;
	conn->server = server;
	llist_add_tail(&conn->entry, &server->conn);
	return conn;
}

static int do_read_tls(struct osmo_pcap_conn *conn, void *buf, size_t want_size)
{
	size_t size = want_size;
	if (conn->tls_limit_read && size > conn->tls_limit_read)
		size = conn->tls_limit_read;
	return gnutls_record_recv(conn->tls_session.session, buf, size);
}

static int do_read(struct osmo_pcap_conn *conn, void *buf, size_t size)
{
	if (conn->direct_read)
		return read(conn->rem_wq.bfd.fd, buf, size);
	return do_read_tls(conn, buf, size);
}

static bool pcap_data_valid(struct osmo_pcap_conn *conn)
{
	unsigned int min_len, max_len;
	switch ((enum OsmoPcapDataType) conn->data->type) {
	case PKT_LINK_HDR:
		if (conn->data->len != sizeof(struct pcap_file_header)) {
			LOGP(DSERVER, LOGL_ERROR,
			     "Implausible llink_hdr length: %u != %zu\n",
			     conn->data->len, sizeof(struct osmo_pcap_pkthdr));
			return false;
		}
		break;
	case PKT_LINK_DATA:
		min_len = sizeof(struct osmo_pcap_pkthdr);
		max_len = conn->server->max_snaplen + sizeof(struct osmo_pcap_pkthdr);
		if (conn->data->len < min_len || conn->data->len > max_len) {
			LOGP(DSERVER, LOGL_ERROR,
			     "Implausible data length: %u < %u <= %u\n",
			     min_len, conn->data->len, max_len);
			return false;
		}
		break;
	default:
		LOGP(DSERVER, LOGL_ERROR, "Unknown data type %" PRIx8 "\n",
		     conn->data->type);
		return false;
	}
	return true;
}

static int read_cb_initial(struct osmo_pcap_conn *conn)
{
	int rc;

	rc = do_read(conn, ((uint8_t*)conn->data) + sizeof(*conn->data) - conn->pend, conn->pend);
	if (rc <= 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Too short packet. Got %d, wanted %d\n", rc, conn->data->len);
		return -1;
	}

	conn->pend -= rc;
	if (conn->pend < 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Someone got the pending read wrong: %d\n", conn->pend);
		return -1;
	} else if (conn->pend == 0) {
		conn->data->len = ntohs(conn->data->len);

		if (!pcap_data_valid(conn))
			return -1;

		conn->state = STATE_DATA;
		conn->pend = conn->data->len;
	}

	return 1;
}

static int read_cb_data(struct osmo_pcap_conn *conn)
{
	int rc;

	rc = do_read(conn, &conn->data->data[conn->data->len - conn->pend], conn->pend);
	if (rc <= 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Too short packet. Got %d, wanted %d\n", rc, conn->data->len);
		return -1;
	}

	conn->pend -= rc;
	if (conn->pend < 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Someone got the pending read wrong: %d\n", conn->pend);
		return -1;
	} else if (conn->pend == 0) {
		conn->state = STATE_INITIAL;
		conn->pend = sizeof(*conn->data);

		/* count the full packet we got */
		rate_ctr_inc(rate_ctr_group_get_ctr(conn->ctrg, PEER_CTR_PKTS));
		rate_ctr_inc(rate_ctr_group_get_ctr(conn->server->ctrg, SERVER_CTR_PKTS));

		/* count the bytes of it */
		rate_ctr_add(rate_ctr_group_get_ctr(conn->ctrg, PEER_CTR_BYTES), conn->data->len);
		rate_ctr_add(rate_ctr_group_get_ctr(conn->server->ctrg, SERVER_CTR_BYTES), conn->data->len);

		switch (conn->data->type) {
		case PKT_LINK_HDR:
			return link_data(conn, conn->data);
			break;
		case PKT_LINK_DATA:
			return write_data(conn, conn->data);
			break;
		}
	}

	return 1;
}

static int dispatch_read(struct osmo_pcap_conn *conn)
{
	if (conn->state == STATE_INITIAL) {
		if (conn->reopen) {
			LOGP(DSERVER, LOGL_INFO, "Reopening log for %s now.\n", conn->name);
			restart_pcap(conn);
			conn->reopen = 0;
		}
		return read_cb_initial(conn);
	} else if (conn->state == STATE_DATA) {
		return read_cb_data(conn);
	}

	return 0;
}

static int read_cb(struct osmo_fd *fd)
{
	struct osmo_pcap_conn *conn;
	int rc;

	conn = fd->data;
	rc = dispatch_read(conn);
	if (rc <= 0)
		close_connection(conn);
	return 0;
}

static void tls_error_cb(struct osmo_tls_session *session)
{
	struct osmo_pcap_conn *conn;
	conn = container_of(session, struct osmo_pcap_conn, tls_session);
	close_connection(conn);
}

static int tls_read_cb(struct osmo_tls_session *session)
{
	struct osmo_pcap_conn *conn;
	size_t pend;
	int rc;

	conn = container_of(session, struct osmo_pcap_conn, tls_session);
	conn->tls_limit_read = 0;
	rc = dispatch_read(conn);
	if (rc <= 0)
		return rc;

	/**
	 * This is a weakness of a single select approach and the
	 * buffered reading here. We need to read everything as
	 * otherwise we do not receive a ready-read. But at the
	 * same time don't read more than is buffered! So cap what
	 * can be read right now.
	 */
	while ((pend = osmo_tls_pending(session)) > 0) {
		conn->tls_limit_read = pend;
		rc = dispatch_read(conn);
		if (rc <= 0)
			return rc;
	}

	return 1;
}

static void new_connection(struct osmo_pcap_server *server,
			   struct osmo_pcap_conn *client, int new_fd)
{
	close_connection(client);

	memset(&client->file_hdr, 0, sizeof(client->file_hdr));
	client->rem_wq.bfd.fd = new_fd;
	if (osmo_fd_register(&client->rem_wq.bfd) != 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to register fd.\n");
		client->rem_wq.bfd.fd = -1;
		close(new_fd);
		return;
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(client->ctrg, PEER_CTR_CONNECT));

	client->state = STATE_INITIAL;
	client->pend = sizeof(*client->data);

	if (client->tls_use && !server->tls_on) {
		LOGP(DSERVER, LOGL_NOTICE,
			"Require TLS but not enabled on conn=%s\n",
			client->name);
		close_connection(client);
		return;
	} else if (client->tls_use) {
		if (!osmo_tls_init_server_session(client, server)) {
			close_connection(client);
			return;
		}
		client->tls_session.error = tls_error_cb;
		client->tls_session.read = tls_read_cb;
		client->direct_read = false;
	} else {
		client->rem_wq.bfd.cb = osmo_wqueue_bfd_cb;
		client->rem_wq.bfd.data = client;
		client->rem_wq.bfd.when = OSMO_FD_READ;
		client->rem_wq.read_cb = read_cb;
		client->direct_read = true;
	}
}

static int accept_cb(struct osmo_fd *fd, unsigned int when)
{
	struct osmo_pcap_conn *conn;
	struct osmo_pcap_server *server;
	struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int new_fd;

	new_fd = accept(fd->fd, (struct sockaddr *) &addr, &size);
	if (new_fd < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to accept socket: %d\n", errno);
		return -1;
	}

	server = fd->data;

	/* count any accept to see no clients */
	rate_ctr_inc(rate_ctr_group_get_ctr(server->ctrg, SERVER_CTR_CONNECT));

	llist_for_each_entry(conn, &server->conn, entry) {
		if (conn->remote_addr.s_addr == addr.sin_addr.s_addr) {
			LOGP(DSERVER, LOGL_NOTICE,
			     "New connection from %s\n", conn->name);
			client_event(conn, "connect", NULL);
			new_connection(server, conn, new_fd);
			return 0;
		}
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(server->ctrg, SERVER_CTR_NOCLIENT));

	/*
	 * TODO: In the future start with a tls handshake and see if we know
	 * this client.
	 */

	LOGP(DSERVER, LOGL_ERROR,
	     "Failed to find client for %s\n", inet_ntoa(addr.sin_addr));
	close(new_fd);
	return -1;
}

int osmo_pcap_server_listen(struct osmo_pcap_server *server)
{
	int fd;

	fd = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
			    server->addr, server->port, OSMO_SOCK_F_BIND);
	if (fd < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to create the server socket.\n");
		return -1;
	}

	server->listen_fd.fd = fd;
	server->listen_fd.when = OSMO_FD_READ;
	server->listen_fd.cb = accept_cb;
	server->listen_fd.data = server;

	if (osmo_fd_register(&server->listen_fd) != 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to register the socket.\n");
		close(fd);
		return -1;
	}

	return 0;
}

void osmo_pcap_server_reopen(struct osmo_pcap_server *server)
{
	struct osmo_pcap_conn *conn;
	LOGP(DSERVER, LOGL_INFO, "Reopening all logfiles.\n");
	llist_for_each_entry(conn, &server->conn, entry) {
		/* Write the complete packet out first */
		if (conn->state == STATE_INITIAL) {
			restart_pcap(conn);
		} else {
			LOGP(DSERVER, LOGL_INFO, "Delaying %s until current packet is complete.\n", conn->name);
			conn->reopen = 1;
		}
	}
}
