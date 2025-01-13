/*
 * osmo-pcap-server code
 *
 * (C) 2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <limits.h>
#include <stdlib.h>
#include <inttypes.h>
#include <libgen.h>

static int validate_link_hdr_pcap(const struct osmo_pcap_conn *conn, const struct osmo_pcap_data *data)
{
	struct pcap_file_header *hdr;

	hdr = (struct pcap_file_header *) &data->data[0];
	if (data->len < sizeof(struct pcap_file_header)) {
		LOGP(DSERVER, LOGL_ERROR,
			"Implausible llink_hdr length: %u < %zu\n",
			data->len, sizeof(struct pcap_file_header));
		return -1;
	}
	if (hdr->snaplen > conn->server->max_snaplen) {
		LOGP(DSERVER, LOGL_ERROR,
		     "The recvd pcap_file_header contains too big snaplen %zu > %zu\n",
		     (size_t) hdr->snaplen, (size_t) conn->server->max_snaplen);
		return -1;
	}
	return 0;
}

static int validate_link_hdr_pcapng(const struct osmo_pcap_conn *conn, const struct osmo_pcap_data *data)
{

	const struct pcapng_block_header *bh = (const struct pcapng_block_header *)&data->data[0];
	const size_t pcapnb_bh_min_len = sizeof(struct pcapng_block_header) + sizeof(uint32_t);
	uint32_t block_total_length, block_type;

	if (data->len < pcapnb_bh_min_len) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible data length: %u < %zu\n",
		     data->len, pcapnb_bh_min_len);
		return -1;
	}

	block_total_length = osmo_pcapng_file_read_uint32((uint8_t *)&bh->block_total_length, conn->pcapng_endian_swapped);
	if (block_total_length & 0x00000003) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible pcapng block total length not multiple of 4: %u\n",
		     block_total_length);
		return -1;
	}

	/* We have a SHB block + N IDB blocks here, so it most probably won't be equal
	 * since we are only checking the 1st SHB block here: */
	if (block_total_length > data->len) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible pcapng block total length: %u > %u\n",
		     block_total_length, data->len);
		return -1;
	}

	block_type = osmo_pcapng_file_read_uint32((uint8_t *)&bh->block_type, conn->pcapng_endian_swapped);
	if (block_type != BLOCK_TYPE_SHB) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible pcapng Block Header type %u vs exp %u\n",
		     block_type, BLOCK_TYPE_SHB);
		return -1;
	}

	/* TODO: validate each idb->snaplen in data->data to be <= conn->server->max_snaplen */

	return 0;
}

static int validate_link_hdr(const struct osmo_pcap_conn *conn, const struct osmo_pcap_data *data)
{

	/* Validation checks: */
	switch (conn->file_fmt) {
	case OSMO_PCAP_FMT_PCAP:
		return validate_link_hdr_pcap(conn, data);
	case OSMO_PCAP_FMT_PCAPNG:
		return validate_link_hdr_pcapng(conn, data);
	default:
		OSMO_ASSERT(0);
	}
}

/* returns >0 on success, <= 0 on failure (closes conn) */
static int rx_link_hdr(struct osmo_pcap_conn *conn, struct osmo_pcap_data *data)
{
	int rc;

	rc = osmo_pcap_file_discover_fmt(data->data, data->len, &conn->file_fmt);
	if (rc < 0)
		return rc;

	if (conn->file_fmt == OSMO_PCAP_FMT_PCAPNG) {
		rc = osmo_pcapng_file_is_swapped(data->data, data->len);
		if (rc < 0) {
			LOGP(DSERVER, LOGL_ERROR, "Unable to figure out pcapng file endianness\n");
			return rc;
		}
		conn->pcapng_endian_swapped = !!rc;
	}

	/* Validation checks: */
	if ((rc = validate_link_hdr(conn, data)) < 0)
		return rc;

	if (conn->store && conn->local_fd < 0) {
		/* First received link hdr in conn */
		talloc_free(conn->file_hdr);
		conn->file_hdr = talloc_size(conn, data->len);
		memcpy(conn->file_hdr, data->data, data->len);
		conn->file_hdr_len = data->len;
		osmo_pcap_conn_restart_trace(conn);
	} else if (conn->file_hdr_len != data->len ||
		   memcmp(&conn->file_hdr, data->data, data->len) != 0) {
		/* Client changed the link hdr in conn */
		talloc_free(conn->file_hdr);
		conn->file_hdr = talloc_size(conn, data->len);
		memcpy(conn->file_hdr, data->data, data->len);
		conn->file_hdr_len = data->len;
		osmo_pcap_conn_restart_trace(conn);
	}

	return 1;
}

static int validate_link_data_pcap(const struct osmo_pcap_conn *conn, const struct osmo_pcap_data *data)
{
	unsigned int min_len, max_len;

	min_len = sizeof(struct osmo_pcap_pkthdr);
	max_len = conn->server->max_snaplen + sizeof(struct osmo_pcap_pkthdr);
	if (data->len < min_len || data->len > max_len) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible data length: %u < %u <= %u\n",
		     min_len, data->len, max_len);
		return -1;
	}
	return 0;
}

/* pcapng: validate size of payload (pkt) in EPB doesn't go through snaplen. */
static int validate_link_data_pcapng(const struct osmo_pcap_conn *conn, const struct osmo_pcap_data *data)
{

	const struct pcapng_block_header *bh = (const struct pcapng_block_header *)&data->data[0];
	const struct pcapng_enhanced_packet_block *epb;
	const size_t pcapnb_bh_min_len = sizeof(struct pcapng_block_header) + sizeof(uint32_t);
	uint32_t block_total_length, block_type, captured_len;

	if (data->len < pcapnb_bh_min_len) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible data length: %u < %zu\n",
		     data->len, pcapnb_bh_min_len);
		return -1;
	}

	block_total_length = osmo_pcapng_file_read_uint32((uint8_t *)&bh->block_total_length, conn->pcapng_endian_swapped);
	if (block_total_length & 0x00000003) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible pcapng block total length not multiple of 4: %u\n",
		     block_total_length);
		return -1;
	}

	if (block_total_length != data->len) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible pcapng block total length: %u != %u\n",
		     block_total_length, data->len);
		return -1;
	}

	block_type = osmo_pcapng_file_read_uint32((uint8_t *)&bh->block_type, conn->pcapng_endian_swapped);
	switch (block_type) {
	case BLOCK_TYPE_EPB:
		if (data->len < pcapnb_bh_min_len + sizeof(struct pcapng_enhanced_packet_block)) {
			LOGP(DSERVER, LOGL_ERROR, "Implausible data length: %u < %zu\n",
			     data->len, pcapnb_bh_min_len + sizeof(struct pcapng_enhanced_packet_block));
			return -1;
		}
		epb = (struct pcapng_enhanced_packet_block *)&bh->block_body[0];
		captured_len = osmo_pcapng_file_read_uint32((uint8_t *)&epb->captured_len, conn->pcapng_endian_swapped);
		if (captured_len > conn->server->max_snaplen) {
			LOGP(DSERVER, LOGL_ERROR, "Implausible pcapng EPB captured length: %u > %u\n",
			     captured_len, conn->server->max_snaplen);
			return -1;
		}
		break;
	default:
		LOGP(DSERVER, LOGL_DEBUG, "Unexpected pcapng Block Header type %u\n", block_type);
		/* Other types exist which we don't specifically support right now, but which may
		 * be sent by newer osmo-pcap-client. Allow storing it without further checks. */
		break;
	}
	return 0;
}

static int validate_link_data(const struct osmo_pcap_conn *conn, const struct osmo_pcap_data *data)
{
	/* Validation checks: */
	switch (conn->file_fmt) {
	case OSMO_PCAP_FMT_PCAP:
		return validate_link_data_pcap(conn, data);
	case OSMO_PCAP_FMT_PCAPNG:
		return validate_link_data_pcapng(conn, data);
	default:
		OSMO_ASSERT(0);
	}
}

/* returns >0 on success, <= 0 on failure (closes conn) */
static int rx_link_data(struct osmo_pcap_conn *conn, struct osmo_pcap_data *data)
{
	int rc;

	if ((rc = validate_link_data(conn, data)) < 0)
		return rc;

	if ((rc = osmo_pcap_conn_process_data(conn, &data->data[0], data->len)))
		return rc;
	return 1;
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

/* Read segment header, struct osmo_pcap_data (without payload)
 * returns >0 on success, <= 0 on failure (closes conn) */
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
	}
	if (conn->pend > 0)
		return 1; /* Wait for more data before continuing */

	conn->data->len = ntohs(conn->data->len);

	if (conn->data->len > conn->data_max_len) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible data length: %u > %zu (snaplen %u)\n",
		     conn->data->len, conn->data_max_len, conn->server->max_snaplen);
		return -1;
	}

	conn->state = STATE_DATA;
	conn->pend = conn->data->len;
	return 1;
}

/* Read segment payload, of size conn->data->len.
 * returns >0 on success, <= 0 on failure (closes conn) */
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
	}
	if (conn->pend > 0)
		return 1; /* Wait for more data before continuing */

	conn->state = STATE_INITIAL;
	conn->pend = sizeof(*conn->data);

	/* count the full packet we got */
	rate_ctr_inc2(conn->ctrg, PEER_CTR_PKTS);
	rate_ctr_inc2(conn->server->ctrg, SERVER_CTR_PKTS);

	/* count the bytes of it */
	rate_ctr_add2(conn->ctrg, PEER_CTR_BYTES, conn->data->len);
	rate_ctr_add2(conn->server->ctrg, SERVER_CTR_BYTES, conn->data->len);

	switch (conn->data->type) {
	case PKT_LINK_HDR:
		rc = rx_link_hdr(conn, conn->data);
		break;
	case PKT_LINK_DATA:
		rc = rx_link_data(conn, conn->data);
		break;
	default:
		OSMO_ASSERT(0);
	}

	if (conn->reopen_delayed) {
		LOGP(DSERVER, LOGL_INFO, "Reopening log for %s now.\n", conn->name);
		osmo_pcap_conn_restart_trace(conn);
		conn->reopen_delayed = false;
	}

	return rc;
}

/* returns >0 on success, <= 0 on failure (closes conn) */
static int dispatch_read(struct osmo_pcap_conn *conn)
{
	if (conn->state == STATE_INITIAL) {
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
		osmo_pcap_conn_close(conn);
	return 0;
}

static void tls_error_cb(struct osmo_tls_session *session)
{
	struct osmo_pcap_conn *conn;
	conn = container_of(session, struct osmo_pcap_conn, tls_session);
	osmo_pcap_conn_close(conn);
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
	osmo_pcap_conn_close(client);

	TALLOC_FREE(client->file_hdr);
	client->file_hdr_len = 0;
	client->rem_wq.bfd.fd = new_fd;
	if (osmo_fd_register(&client->rem_wq.bfd) != 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to register fd.\n");
		client->rem_wq.bfd.fd = -1;
		close(new_fd);
		return;
	}

	rate_ctr_inc2(client->ctrg, PEER_CTR_CONNECT);

	/* Prepare for first read of segment header: */
	client->state = STATE_INITIAL;
	client->pend = sizeof(*client->data);

	if (client->tls_use && !server->tls_on) {
		LOGP(DSERVER, LOGL_NOTICE,
			"Require TLS but not enabled on conn=%s\n",
			client->name);
		osmo_pcap_conn_close(client);
		return;
	} else if (client->tls_use) {
		if (!osmo_tls_init_server_session(client, server)) {
			osmo_pcap_conn_close(client);
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
	rate_ctr_inc2(server->ctrg, SERVER_CTR_CONNECT);

	llist_for_each_entry(conn, &server->conn, entry) {
		if (conn->remote_addr.s_addr == addr.sin_addr.s_addr) {
			LOGP(DSERVER, LOGL_NOTICE,
			     "New connection from %s\n", conn->name);
			osmo_pcap_conn_event(conn, "connect", NULL);
			new_connection(server, conn, new_fd);
			return 0;
		}
	}

	rate_ctr_inc2(server->ctrg, SERVER_CTR_NOCLIENT);

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
