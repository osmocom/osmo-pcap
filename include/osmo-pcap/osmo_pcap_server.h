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

#ifndef OSMO_PCAP_SERVER_H
#define OSMO_PCAP_SERVER_H

#include "wireformat.h"
#include "osmo_tls.h"

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

#include <stdbool.h>
#include <time.h>

struct rate_ctr_group;
struct rate_ctr_group_desc;

struct osmo_pcap_server;


#define STATE_INITIAL	0
#define STATE_DATA	1

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

struct osmo_pcap_conn {
	/* list of connections */
	struct llist_head entry;
	struct osmo_pcap_server *server;

	/* name */
	char *name;
	char *remote_host;
	int no_store;
	struct in_addr remote_addr;

	/* Remote connection */
	struct osmo_wqueue rem_wq;
	int local_fd;
	char *curr_filename;

	/* pcap stuff */
	struct pcap_file_header file_hdr;

	/* last time */
	struct tm last_write;

	/* read buffering */
	int state;
	int pend;
	int reopen;
	struct osmo_pcap_data *data;

	/* statistics */
	struct rate_ctr_group *ctrg;

	/* tls */
	bool tls_use;
	bool direct_read;
	size_t tls_limit_read;
	struct osmo_tls_session tls_session;
};

struct osmo_pcap_server {
	struct llist_head conn;

	int port;
	char *addr;
	struct osmo_fd listen_fd;

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
	mode_t permission_mask;
	off_t max_size;
	int max_snaplen;

	/* statistics */
	struct rate_ctr_group *ctrg;
};

extern struct osmo_pcap_server *pcap_server;
extern const struct rate_ctr_group_desc pcap_peer_group_desc;

void osmo_pcap_server_reopen(struct osmo_pcap_server *server);
int osmo_pcap_server_listen(struct osmo_pcap_server *server);
struct osmo_pcap_conn *osmo_pcap_server_find(struct osmo_pcap_server *ser,
					     const char *name);
void osmo_pcap_server_delete(struct osmo_pcap_conn *conn);
void vty_server_init(void);
void osmo_pcap_server_close_trace(struct osmo_pcap_conn *conn);
void osmo_pcap_server_close_conn(struct osmo_pcap_conn *conn);

#endif
