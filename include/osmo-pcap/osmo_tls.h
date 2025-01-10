/*
 * osmo-pcap TLS code
 *
 * (C) 2016 by Holger Hans Peter Freyther <holger@moiji-mobile.com>
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
#include <stdint.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

struct osmo_fd;
struct osmo_wqueue;
struct osmo_pcap_client_conn;
struct osmo_pcap_conn;
struct osmo_pcap_server;

struct osmo_tls_session {
	bool in_use;
	bool need_handshake;
	bool need_resend;
	gnutls_session_t session;

	/* any credentials */
	bool anon_alloc;
	gnutls_anon_client_credentials_t anon_cred;
	bool anon_serv_alloc;
	gnutls_anon_server_credentials_t anon_serv_cred;

	/* a x509 cert credential */
	bool cert_alloc;
	gnutls_certificate_credentials_t cert_cred;

	/* the private certificate */
	bool pcert_alloc;
	gnutls_pcert_st pcert;

	/* the private key in _RAM_ */
	bool privk_alloc;
	gnutls_privkey_t privk;

	struct osmo_wqueue *wqueue;

	int (*read)(struct osmo_tls_session *session);
	void (*error)(struct osmo_tls_session *session);
	void (*handshake_done)(struct osmo_tls_session *session);
};

void osmo_tls_init(void);

bool osmo_tls_init_client_session(struct osmo_pcap_client_conn *conn);


bool osmo_tls_init_server_session(struct osmo_pcap_conn *conn, struct osmo_pcap_server *server);
void osmo_tls_release(struct osmo_tls_session *);

int osmo_tls_client_bfd_cb(struct osmo_fd *fd, unsigned int what);

size_t osmo_tls_pending(struct osmo_tls_session *session);
void osmo_tls_server_init(struct osmo_pcap_server *server);

void osmo_tls_dh_load(struct osmo_pcap_server *server);
void osmo_tls_dh_generate(struct osmo_pcap_server *server);
