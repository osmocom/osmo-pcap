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
#pragma once

#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/socket.h>
#include <osmocom/netif/stream.h>

#include <osmo-pcap/wireformat.h>
#include <osmo-pcap/osmo_tls.h>
#include <osmo-pcap/osmo_pcap_file.h>

struct rate_ctr_group;
struct rate_ctr_group_desc;

struct osmo_pcap_server;


#define STATE_INITIAL	0
#define STATE_DATA	1

/*! Rate counter interval */
enum time_interval {
	TIME_INTERVAL_SEC,	/*!< second */
	TIME_INTERVAL_MIN,	/*!< minute */
	TIME_INTERVAL_HOUR,	/*!< hour */
	TIME_INTERVAL_DAY,	/*!< day */
	TIME_INTERVAL_MONTH,	/*!< month */
	TIME_INTERVAL_YEAR,	/*!< year */
};

enum {
	PEER_CTR_CONNECT,
	PEER_CTR_BYTES,
	PEER_CTR_PKTS,
	PEER_CTR_PROTATE,
};

enum {
	SERVER_CTR_CONNECT,
	SERVER_CTR_BYTES,
	SERVER_CTR_PKTS,
	SERVER_CTR_PROTATE,
	SERVER_CTR_NOCLIENT,
};

struct osmo_pcap_wr_file;
typedef void (*osmo_pcap_wr_file_flush_completed_cb_t)(struct osmo_pcap_wr_file *wrf, void *data);
struct osmo_pcap_wr_file {
	struct llist_head entry; /* entry into (osmo_pcap_conn)->wrf_flushing_list */
	void *data; /* user backpointer */
	/* canonicalized absolute pathname of pcap file we write to */
	char *filename;
	/* file descriptor of the file we write to */
	struct osmo_io_fd *local_iofd;
	/* Current write offset of the file we write to (local_fd) */
	off_t wr_offset;
	/* Number of bytes confirmed to be written, <=wr_offset */
	off_t wr_completed;
	osmo_pcap_wr_file_flush_completed_cb_t flush_completed_cb;
};
struct osmo_pcap_wr_file *osmo_pcap_wr_file_alloc(void *ctx, void *data);
void osmo_pcap_wr_file_free(struct osmo_pcap_wr_file *wrf);
void osmo_pcap_wr_file_set_flush_completed_cb(struct osmo_pcap_wr_file *wrf, osmo_pcap_wr_file_flush_completed_cb_t flush_completed_cb);
int osmo_pcap_wr_file_open(struct osmo_pcap_wr_file *wrf, const char *filename, mode_t mode);
void osmo_pcap_wr_file_close(struct osmo_pcap_wr_file *wrf);
int osmo_pcap_wr_file_write_msgb(struct osmo_pcap_wr_file *wrf, struct msgb *msg);
bool osmo_pcap_wr_file_has_pending_writes(const struct osmo_pcap_wr_file *wrf);
int osmo_pcap_wr_file_flush(struct osmo_pcap_wr_file *wrf, struct llist_head *wrf_flushing_list);
bool osmo_pcap_wr_file_is_flushing(const struct osmo_pcap_wr_file *wrf);
void osmo_pcap_wr_file_move_to_dir(struct osmo_pcap_wr_file *wrf, const char *dst_dirpath);

struct osmo_pcap_conn {
	/* list of connections */
	struct llist_head entry;
	struct osmo_pcap_server *server;

	/* name */
	char *name;
	char *remote_host;
	bool store;
	struct osmo_sockaddr rem_addr;

	/* Remote connection */
	struct osmo_stream_srv *srv;
	struct osmo_pcap_wr_file *wrf;
	/* list of osmo_pcap_wr_file->entry.
	 * wrf which we want to close but still have pending writes to be completed */
	struct llist_head wrf_flushing_list;

	/* pcap stuff */
	enum osmo_pcap_fmt file_fmt;
	bool pcapng_endian_swapped;
	struct msgb *file_hdr_msg;

	/* last time */
	struct tm last_write;

	/* read buffering */
	int state;
	bool reopen_delayed;
	size_t data_max_len; /* size of allocated buffer in data->data. */

	/* statistics */
	struct rate_ctr_group *ctrg;

	/* tls */
	bool tls_use;
	size_t tls_limit_read;
	struct osmo_tls_session tls_session;
	struct osmo_wqueue rem_wq;
	struct msgb *rx_tls_dec_msg; /* Used to store TLS decoded data */
};

void osmo_pcap_conn_free(struct osmo_pcap_conn *conn);
void vty_server_init(void);
void osmo_pcap_conn_close(struct osmo_pcap_conn *conn);
int osmo_pcap_conn_process_data(struct osmo_pcap_conn *conn, struct msgb *msg);
void osmo_pcap_conn_restart_trace(struct osmo_pcap_conn *conn);
void osmo_pcap_conn_close_trace(struct osmo_pcap_conn *conn);
void osmo_pcap_conn_event(struct osmo_pcap_conn *conn,
			  const char *event, const char *data);

struct osmo_pcap_server {
	struct llist_head conn;

	int port;
	char *addr;
	struct osmo_stream_srv_link *srv_link;

	/* zeromq handling */
	int zmq_port;
	char *zmq_ip;
	void *zmq_ctx;
	void *zmq_publ;

	/* tls base */
	bool tls_on;
	bool tls_allow_anon;
	bool tls_allow_x509;
	unsigned tls_log_level;
	char *tls_priority;
	char *tls_capath;
	char *tls_crlfile;
	char *tls_server_cert;
	char *tls_server_key;
	char *tls_dh_pkcs3;
	gnutls_dh_params_t dh_params;
	bool dh_params_allocated;

	char *base_path;
	char *completed_path;
	mode_t permission_mask;
	off_t max_size;
	bool max_size_enabled;
	int max_snaplen;

	struct {
		bool enabled;
		enum time_interval intv;
		unsigned int modulus;
	} rotate_localtime;

	/* statistics */
	struct rate_ctr_group *ctrg;
};

extern struct osmo_pcap_server *pcap_server;
extern const struct rate_ctr_group_desc pcap_peer_group_desc;
extern const struct rate_ctr_group_desc pcap_server_group_desc;
struct osmo_pcap_server *osmo_pcap_server_alloc(void *ctx);
void osmo_pcap_server_free(struct osmo_pcap_server *psrv);
void osmo_pcap_server_reopen(struct osmo_pcap_server *server);
int osmo_pcap_server_listen(struct osmo_pcap_server *server);
struct osmo_pcap_conn *osmo_pcap_server_find_or_create(struct osmo_pcap_server *ser,
					     const char *name);
