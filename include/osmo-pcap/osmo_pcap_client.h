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

#include "osmo_tls.h"

#include <inttypes.h>
#include <pcap.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/write_queue.h>

struct rate_ctr_group;

#define WQUEUE_MAXLEN_DEFAULT 1000

enum {
	CLIENT_CTR_CONNECT,
	CLIENT_CTR_BYTES,
	CLIENT_CTR_PKTS,
	CLIENT_CTR_2BIG,
	CLIENT_CTR_NOMEM,
	CLIENT_CTR_QERR,
	CLIENT_CTR_PERR,
	CLIENT_CTR_WERR,
	CLIENT_CTR_P_RECV,
	CLIENT_CTR_P_DROP,
	CLIENT_CTR_P_IFDROP,
};

enum osmo_pcap_protocol {
	PROTOCOL_OSMOPCAP,
	PROTOCOL_IPIP,
};

struct osmo_pcap_client_conn {
	struct llist_head entry;
	const char *name;

	char *srv_ip;
	int srv_port;
	char *source_ip;
	struct osmo_wqueue wqueue;
	struct osmo_timer_list timer;
	enum osmo_pcap_protocol protocol;

	/* TLS handling */
	bool tls_on;
	bool tls_verify;
	char *tls_hostname;
	char *tls_capath;
	char *tls_priority;

	char *tls_client_cert;
	char *tls_client_key;

	unsigned tls_log_level;

	struct osmo_tls_session tls_session;

	/* back pointer */
	struct osmo_pcap_client *client;
};

struct osmo_pcap_handle {
	struct llist_head entry; /* item in (struct osmo_pcap_client)->handles */
	struct osmo_pcap_client *client; /* back pointer */
	char *devname;
	pcap_t *handle;
	struct osmo_fd fd;
	u_int last_ps_recv;
	u_int last_ps_drop;
	u_int last_ps_ifdrop;
	struct osmo_timer_list pcap_stat_timer;
	struct bpf_program bpf;
};

struct osmo_pcap_client {
	struct llist_head handles; /* list of struct osmo_pcap_handle */

	char *filter_string;
	int filter_itself;
	int gprs_filtering;
	int snaplen;

	struct osmo_pcap_client_conn *conn;
	struct llist_head conns;

	/* statistics */
	struct rate_ctr_group *ctrg;
};

extern struct osmo_pcap_client *pcap_client;

struct osmo_pcap_client *osmo_pcap_client_alloc(void *tall_ctx);
int vty_client_init(void);

int osmo_client_start_capture(struct osmo_pcap_client *client);
int osmo_client_filter(struct osmo_pcap_client *client, const char *filter);

struct osmo_pcap_client_conn *osmo_client_find_or_create_conn(struct osmo_pcap_client *, const char *name);
struct osmo_pcap_client_conn *osmo_client_find_conn(struct osmo_pcap_client *, const char *name);

struct osmo_pcap_handle *osmo_client_find_handle(struct osmo_pcap_client *client, const char *devname);

struct osmo_pcap_client_conn *osmo_client_conn_alloc(struct osmo_pcap_client *client, const char *name);
void osmo_client_conn_free(struct osmo_pcap_client_conn *conn);
void osmo_client_conn_send_data(struct osmo_pcap_client_conn *conn,
				struct pcap_pkthdr *hdr, const uint8_t *data);
void osmo_client_conn_send_link(struct osmo_pcap_client_conn *conn);
void osmo_client_conn_connect(struct osmo_pcap_client_conn *conn);
void osmo_client_conn_disconnect(struct osmo_pcap_client_conn *conn);
void osmo_client_conn_reconnect(struct osmo_pcap_client_conn *conn);


struct osmo_pcap_handle *osmo_pcap_handle_alloc(struct osmo_pcap_client *client, const char *devname);
void osmo_pcap_handle_free(struct osmo_pcap_handle *ph);
int osmo_pcap_handle_start_capture(struct osmo_pcap_handle *ph);

#define LOGCONN(conn, lvl, fmt, args...) \
	LOGP(DCLIENT, lvl, "CONN(%s,%s:%d) " fmt, (conn)->name, (conn)->srv_ip, (conn)->srv_port, ## args)

#define LOGPH(ph, lvl, fmt, args...) \
	LOGP(DCLIENT, lvl, "PH(%s) " fmt, (ph)->devname, ## args)
