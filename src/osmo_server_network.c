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

#include <osmocom/core/byteswap.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>

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

/* Updates conn->file_hdr_msg, owns (frees) msg. */
static void update_conn_file_hdr_msg(struct osmo_pcap_conn *conn, struct msgb *msg)
{
	/* The msg chunk of memory to hold the hdr data may actually be a lot bigger than
	 * the actual data (len << data_len).
	 * Hence, since we may keep this around for a big time (life of the conn), let's
	 * better keep a reduced memory footprint msgb instead of the original one: */
	msgb_free(conn->file_hdr_msg);
	conn->file_hdr_msg = msgb_copy_resize_c(conn, msg, msgb_length(msg), "conn_file_hdr_msg");
	OSMO_ASSERT(conn->file_hdr_msg);
	msgb_free(msg);

	/* pull to l2 is done here at the copy since anyway msgb_copy_resize
	 * cannot shrink available headroom: */
	msgb_pull_to_l2(conn->file_hdr_msg);

	osmo_pcap_conn_restart_trace(conn);
}

/* returns >0 on success (msg becomes owned), <= 0 on failure (closes conn) */
static int rx_link_hdr(struct osmo_pcap_conn *conn, struct msgb *msg)
{
	struct osmo_pcap_data *data = (struct osmo_pcap_data *)msg->l1h;
	int rc;

	rc = osmo_pcap_file_discover_fmt(data->data, data->len, &conn->file_fmt);
	if (rc < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Unable to figure out pcap vs pcapng file format (len=%u): %s\n",
		     data->len, osmo_hexdump(data->data, OSMO_MIN(data->len, 32)));
		return rc;
	}

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

	if (conn->store && !conn->wrf) {
		/* First received link hdr in conn */
		update_conn_file_hdr_msg(conn, msg);
	} else if (msgb_l2len(conn->file_hdr_msg) != msgb_l2len(msg) ||
		   memcmp(msgb_l2(conn->file_hdr_msg), msgb_l2(msg), msgb_l2len(msg)) != 0) {
		/* Client changed the link hdr in conn */
		update_conn_file_hdr_msg(conn, msg);
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
static int rx_link_data(struct osmo_pcap_conn *conn, struct msgb *msg)
{
	int rc;

	if ((rc = validate_link_data(conn, (struct osmo_pcap_data *)msg->l1h)) < 0)
		return rc;

	msgb_pull_to_l2(msg);
	if ((rc = osmo_pcap_conn_process_data(conn, msg)) < 0)
		return rc;
	return 1;
}

/* Read segment payload, of size data->len.
 * returns >0 on success, <= 0 on failure (closes conn).
 * Message is always owned or freed here. */
static int rx_link(struct osmo_pcap_conn *conn, struct msgb *msg)
{
	struct osmo_pcap_data *data = (struct osmo_pcap_data *)msg->l1h;
	int rc;

	/* count the full packet we got */
	rate_ctr_inc2(conn->ctrg, PEER_CTR_PKTS);
	rate_ctr_inc2(conn->server->ctrg, SERVER_CTR_PKTS);

	/* count the bytes of it */
	rate_ctr_add2(conn->ctrg, PEER_CTR_BYTES, data->len);
	rate_ctr_add2(conn->server->ctrg, SERVER_CTR_BYTES, data->len);

	switch (data->type) {
	case PKT_LINK_HDR:
		rc = rx_link_hdr(conn, msg);
		break;
	case PKT_LINK_DATA:
		rc = rx_link_data(conn, msg);
		break;
	default:
		OSMO_ASSERT(0);
	}

	if (rc <= 0)
		msgb_free(msg);

	if (conn->reopen_delayed) {
		LOGP(DSERVER, LOGL_INFO, "Reopening log for %s now.\n", conn->name);
		osmo_pcap_conn_restart_trace(conn);
		conn->reopen_delayed = false;
	}

	return rc;
}

static int do_read_tls(struct osmo_pcap_conn *conn, void *buf, size_t want_size)
{
	size_t size = want_size;
	if (conn->tls_limit_read && size > conn->tls_limit_read)
		size = conn->tls_limit_read;
	return gnutls_record_recv(conn->tls_session.session, buf, size);
}

/* Read segment header, struct osmo_pcap_data (without payload)
 * returns >0 on success, <= 0 on failure (closes conn) */
static int tls_read_cb_initial(struct osmo_pcap_conn *conn)
{
	int rc;
	struct msgb *msg = conn->rx_tls_dec_msg;
	msg->l1h = msgb_data(msg);
	struct osmo_pcap_data *pdata = (struct osmo_pcap_data *)msg->l1h;
	size_t pend = sizeof(*pdata) - msgb_length(msg);

	OSMO_ASSERT(sizeof(*pdata) > msgb_length(msg));

	rc = do_read_tls(conn, msg->tail, pend);
	if (rc <= 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Too short packet. Got %d, wanted %zu\n", rc, pend);
		return -1;
	}
	if (rc > pend) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Someone got the pending read wrong: %zu\n", pend);
		return -1;
	}
	msgb_put(msg, rc);

	if (pend > rc)
		return 1; /* Wait for more data before continuing */

	pdata->len = ntohs(pdata->len);

	if (pdata->len + sizeof(*pdata) > conn->data_max_len) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible data length: %u > %zu (snaplen %u)\n",
		     pdata->len, conn->data_max_len, conn->server->max_snaplen);
		return -1;
	}

	conn->state = STATE_DATA;
	msg->l2h = msg->tail;
	return 1;
}

static int tls_read_cb_data(struct osmo_pcap_conn *conn)
{
	int rc;
	struct msgb *msg = conn->rx_tls_dec_msg;
	struct osmo_pcap_data *pdata = (struct osmo_pcap_data *)msg->l1h;
	size_t pend = pdata->len - msgb_l2len(msg);

	rc = do_read_tls(conn, msg->tail, pend);
	if (rc <= 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Too short packet. Got %d, wanted %u\n", rc, pdata->len);
		return -1;
	}
	if (rc > pend) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Someone got the pending read wrong: %zu\n", pend);
		return -1;
	}
	msgb_put(msg, rc);

	if (pend > rc)
		return 1; /* Wait for more data before continuing */

	conn->state = STATE_INITIAL;
	conn->rx_tls_dec_msg = msgb_alloc_c(conn, conn->data_max_len, "rx_tls_dec_data");

	return rx_link(conn, msg);
}

/* returns >0 on success, <= 0 on failure (closes conn) */
static int tls_dispatch_read(struct osmo_pcap_conn *conn)
{
	if (conn->state == STATE_INITIAL) {
		return tls_read_cb_initial(conn);
	} else if (conn->state == STATE_DATA) {
		return tls_read_cb_data(conn);
	}

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
	rc = tls_dispatch_read(conn);
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
		rc = tls_dispatch_read(conn);
		if (rc <= 0)
			return rc;
	}

	return 1;
}

int conn_read_cb(struct osmo_stream_srv *srv, int res, struct msgb *msg)
{
	struct osmo_pcap_conn *conn = osmo_stream_srv_get_data(srv);
	struct osmo_pcap_data *data;
	int rc;

	if (res <= 0) {
		LOGP(DSERVER, LOGL_ERROR, "Read from conn failed: %d\n", res);
		osmo_pcap_conn_close(conn);
		return 0;
	}

	OSMO_ASSERT(msgb_length(msg) >= sizeof(*data));

	msg->l1h = msgb_data(msg);
	data = (struct osmo_pcap_data *)msg->l1h;
	data->len = osmo_ntohs(data->len);

	msg->l2h = msg->l1h + sizeof(*data);

	rc = rx_link(conn, msg);
	if (rc <= 0)
		osmo_pcap_conn_close(conn);
	return 0;
}

int conn_segmentation_cb2(struct osmo_stream_srv *srv, struct msgb *msg)
{
	struct osmo_pcap_conn *conn = osmo_stream_srv_get_data(srv);

	const struct osmo_pcap_data *hh = (struct osmo_pcap_data *) msgb_data(msg);
	size_t payload_len, total_len;
	size_t available = msgb_length(msg) + msgb_tailroom(msg);

	if (msgb_length(msg) < sizeof(*hh)) {
		/* Haven't even read the entire header */
		return -EAGAIN;
	}
	payload_len = osmo_ntohs(hh->len);
	total_len = sizeof(*hh) + payload_len;

	if (OSMO_UNLIKELY(total_len > conn->data_max_len)) {
		LOGP(DSERVER, LOGL_ERROR, "Implausible data length: %zu > %zu (snaplen %u)\n",
		     total_len, conn->data_max_len, conn->server->max_snaplen);
		return -ENOBUFS;
	}

	if (OSMO_UNLIKELY(total_len > available)) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Not enough space left in message buffer. Have %zu octets, but need %zu\n",
		     available, total_len);
		return -ENOBUFS;
	}
	return total_len;
}

static void new_connection(struct osmo_pcap_server *server,
			   struct osmo_pcap_conn *conn, int new_fd)
{
	osmo_pcap_conn_close(conn);

	rate_ctr_inc2(conn->ctrg, PEER_CTR_CONNECT);

	if (conn->tls_use && !server->tls_on) {
		LOGP(DSERVER, LOGL_NOTICE, "Require TLS but not enabled on conn=%s\n", conn->name);
		close(new_fd);
		return;
	}

	if (conn->tls_use) {
		conn->rem_wq.bfd.fd = new_fd;
		if (osmo_fd_register(&conn->rem_wq.bfd) != 0) {
			LOGP(DSERVER, LOGL_ERROR, "Failed to register fd.\n");
			conn->rem_wq.bfd.fd = -1;
			close(new_fd);
			return;
		}
		/* Prepare for first read of segment header: */
		conn->state = STATE_INITIAL;
		conn->rx_tls_dec_msg = msgb_alloc_c(conn, conn->data_max_len, "rx_tls_dec_data");
		if (!osmo_tls_init_server_session(conn, server)) {
			osmo_pcap_conn_close(conn);
			return;
		}
		conn->tls_session.error = tls_error_cb;
		conn->tls_session.read = tls_read_cb;
	} else {
		osmo_stream_srv_link_set_msgb_alloc_info(server->srv_link, conn->data_max_len, 0);
		conn->srv = osmo_stream_srv_create2(conn, server->srv_link, new_fd, conn);
		OSMO_ASSERT(conn->srv);
		osmo_stream_srv_set_name(conn->srv, "pcap_conn");
		osmo_stream_srv_set_read_cb(conn->srv, conn_read_cb);
		osmo_stream_srv_set_segmentation_cb2(conn->srv, conn_segmentation_cb2);
	}
}

static int accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_pcap_conn *conn = NULL;
	struct osmo_pcap_server *server = osmo_stream_srv_link_get_data(link);
	char str[INET6_ADDRSTRLEN];
	struct osmo_sockaddr osa;
	socklen_t len = sizeof(osa.u.sas);
	int rc;

	memset(&osa, 0, sizeof(osa));
	rc = getpeername(fd, &osa.u.sa, &len);
	if (rc < 0) {
		LOGP(DSERVER, LOGL_ERROR, "getpeername() failed during accept(): %d\n", errno);
		return -1;
	}

	/* count any accept to see no clients */
	rate_ctr_inc2(server->ctrg, SERVER_CTR_CONNECT);

	llist_for_each_entry(conn, &server->conn, entry) {
		if (conn->rem_addr.u.sa.sa_family != osa.u.sa.sa_family)
			continue;
		switch (conn->rem_addr.u.sa.sa_family) {
		case AF_INET:
			if (conn->rem_addr.u.sin.sin_addr.s_addr != osa.u.sin.sin_addr.s_addr)
				continue;
			goto found;
		case AF_INET6:
			if (memcmp(&conn->rem_addr.u.sin6.sin6_addr, &osa.u.sin6.sin6_addr, sizeof(struct in6_addr)))
				continue;
			goto found;
		default:
			continue;
		};
	}

	rate_ctr_inc2(server->ctrg, SERVER_CTR_NOCLIENT);

	/*
	 * TODO: In the future start with a tls handshake and see if we know
	 * this client.
	 */

	LOGP(DSERVER, LOGL_ERROR, "Failed to find client for %s\n",
	     osmo_sockaddr_ntop(&osa.u.sa, str));
	close(fd);
	return -1;

found:
	LOGP(DSERVER, LOGL_NOTICE, "New connection from %s\n", conn->name);
	osmo_pcap_conn_event(conn, "connect", NULL);
	new_connection(server, conn, fd);
	return 0;
}

int osmo_pcap_server_listen(struct osmo_pcap_server *psrv)
{
	osmo_stream_srv_link_set_addr(psrv->srv_link, psrv->addr);
	osmo_stream_srv_link_set_port(psrv->srv_link, psrv->port);
	osmo_stream_srv_link_set_accept_cb(psrv->srv_link, accept_cb);
	if (osmo_stream_srv_link_open(psrv->srv_link)) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to create the server socket.\n");
		return -1;
	}

	return 0;
}
