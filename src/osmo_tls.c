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

#include <osmo-pcap/osmo_tls.h>
#include <osmo-pcap/osmo_pcap_client.h>
#include <osmo-pcap/osmo_pcap_server.h>
#include <osmo-pcap/common.h>

#include <osmocom/core/write_queue.h>
#include <osmocom/core/talloc.h>

#include <string.h>

#define CHECK_RC(rc, str) \
		if (rc != 0) { \
			LOGP(DTLS, LOGL_ERROR, "%s with rc=%d\n", str, rc); \
			exit(1); \
		}

static int generate_dh_params(struct osmo_pcap_server *server)
{
	int rc;
	unsigned int bits =  gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
							GNUTLS_SEC_PARAM_HIGH);

	LOGP(DTLS, LOGL_NOTICE, "Going to create DH params for %d bits\n", bits);

	/* allocate it */
	rc = gnutls_dh_params_init (&server->dh_params);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "Failed to allocate DH params rc=%d\n", rc);
		server->dh_params_allocated = false;
		return rc;
	}

	/* generate and check */
	rc = gnutls_dh_params_generate2 (server->dh_params, bits);
	if (rc == GNUTLS_E_SUCCESS)
		server->dh_params_allocated = true;
	else {
		LOGP(DTLS, LOGL_ERROR, "Failed to generate DH params rc=%d\n", rc);
		server->dh_params_allocated = false;
		gnutls_dh_params_deinit(server->dh_params);
	}
	return rc;
}

void osmo_tls_dh_load(struct osmo_pcap_server *server)
{
	gnutls_datum_t data;
	int rc;

	/* free it before we start */
	if (server->dh_params_allocated) {
		gnutls_dh_params_deinit(server->dh_params);
		server->dh_params_allocated = false;
	}
	/* check if we have all data */
	if (!server->tls_dh_pkcs3) {
		LOGP(DTLS, LOGL_ERROR, "Can not generate missing pkcs3=%p\n",
			server->tls_dh_pkcs3);
		return;
	}
	/* initialize it again */
	rc = gnutls_dh_params_init (&server->dh_params);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "Failed to allocate DH params rc=%d\n", rc);
		server->dh_params_allocated = false;
		return;
	}
	/* load prime and generator */
	rc = gnutls_load_file(server->tls_dh_pkcs3, &data);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "Failed to load DH params from=%s rc=%d\n",
			server->tls_dh_pkcs3, rc);
		gnutls_dh_params_deinit(server->dh_params);
		return;
	}
	rc = gnutls_dh_params_import_pkcs3(server->dh_params, &data, GNUTLS_X509_FMT_PEM);
	gnutls_free(data.data);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "Failed to import DH params rc=%d\n", rc);
		gnutls_dh_params_deinit(server->dh_params);
		return;
	}
	/* done */
	server->dh_params_allocated = true;
}

void osmo_tls_dh_generate(struct osmo_pcap_server *server)
{
	if (server->dh_params_allocated)
		gnutls_dh_params_deinit(server->dh_params);
	generate_dh_params(server);
}

static int cert_callback(gnutls_session_t tls_session,
				const gnutls_datum_t * req_ca_rdn, int nreqs,
				const gnutls_pk_algorithm_t * sign_algos,
				int sign_algos_length, gnutls_pcert_st ** pcert,
				unsigned int *pcert_length, gnutls_privkey_t * pkey)
{
	struct osmo_tls_session *sess = gnutls_session_get_ptr(tls_session);
	gnutls_certificate_type_t type;

	LOGP(DTLS, LOGL_DEBUG, "cert callback from server\n");
	type = gnutls_certificate_type_get(tls_session);
	if (type != GNUTLS_CRT_X509)
		return -1;

	*pcert_length = 1;
	*pcert = &sess->pcert;
	*pkey = sess->privk;
	return 0;
}

static void tls_log_func(int level, const char *str)
{
	LOGP(DTLS, LOGL_DEBUG, "GNUtls: |<%d>| %s", level, str);
}

static int verify_cert_cb(gnutls_session_t session)
{
	const char *hostname;
	unsigned int status;
	int ret;

	hostname = gnutls_session_get_ptr(session);
	ret = gnutls_certificate_verify_peers3(session,
				hostname, &status);
	if (ret != 0)
		return GNUTLS_E_CERTIFICATE_ERROR;
	if (status != 0)
		return GNUTLS_E_CERTIFICATE_ERROR;
	return 0;
}

static void release_keys(struct osmo_tls_session *sess)
{
	if (sess->pcert_alloc) {
		gnutls_pcert_deinit(&sess->pcert);
		sess->pcert_alloc = false;
	}
	if (sess->privk_alloc) {
		gnutls_privkey_deinit(sess->privk);
		sess->privk_alloc = false;
	}
}

void osmo_tls_init(void)
{
	int rc;
	rc = gnutls_global_init();
	CHECK_RC(rc, "init failed");
        gnutls_global_set_log_function(tls_log_func);
}

void osmo_tls_server_init(struct osmo_pcap_server *server)
{
	int rc;

	if (server->dh_params_allocated)
		return;
	rc = generate_dh_params(server);
	CHECK_RC(rc, "dh params failed");
}

static int need_handshake(struct osmo_tls_session *tls_session)
{
	int rc;

	rc = gnutls_handshake(tls_session->session);
	if (rc == 0) {
		/* handshake is done. start writing if we are allowed to */
		LOGP(DTLS, LOGL_NOTICE, "TLS handshake done.\n");
		osmo_fd_read_enable(&tls_session->wqueue->bfd);
		if (!llist_empty(&tls_session->wqueue->msg_queue))
			osmo_fd_write_enable(&tls_session->wqueue->bfd);
		tls_session->need_handshake = false;
		release_keys(tls_session);
		if (tls_session->handshake_done)
			tls_session->handshake_done(tls_session);
	} else if (rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED) {
		LOGP(DTLS, LOGL_DEBUG, "rc=%d will wait for writable again.\n", rc);
	} else if (gnutls_error_is_fatal(rc)) {
		/* it failed for good.. */
		LOGP(DTLS, LOGL_ERROR, "handshake failed rc=%d str=%s\n",
			rc, gnutls_strerror(rc));
		tls_session->wqueue->bfd.when = 0;
		tls_session->error(tls_session);
	}
	return 0;
}

static int tls_read(struct osmo_tls_session *sess)
{
	char buf[1024];
	int rc;

	if (sess->read)
		return sess->read(sess);

	memset(buf, 0, sizeof(buf));
	rc = gnutls_record_recv(sess->session, buf, sizeof(buf) - 1);
	return rc;
}

static int tls_write(struct osmo_tls_session *sess)
{
	int rc;
	osmo_fd_write_disable(&sess->wqueue->bfd);

	if (llist_empty(&sess->wqueue->msg_queue))
		return 0;

	if (sess->need_resend) {
		rc = gnutls_record_send(sess->session, NULL, 0);
	} else {
		struct msgb *msg;
		msg = (struct msgb *) sess->wqueue->msg_queue.next;
		rc = gnutls_record_send(sess->session, msg->data, msg->len);
	}

	if (rc > 0) {
		sess->wqueue->current_length -= 1;
		sess->need_resend = false;
		struct msgb *msg = msgb_dequeue(&sess->wqueue->msg_queue);
		msgb_free(msg);
	} else if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
		sess->need_resend = true;
	} else if (gnutls_error_is_fatal(rc)) {
		return rc;
	}

	if (sess->need_resend || !llist_empty(&sess->wqueue->msg_queue))
		osmo_fd_write_enable(&sess->wqueue->bfd);
	return rc;
}

int osmo_tls_client_bfd_cb(struct osmo_fd *fd, unsigned what)
{
	struct osmo_tls_session *sess = fd->data;

	if (sess->need_handshake)
		return need_handshake(sess);

	if (what & OSMO_FD_READ) {
		int rc = tls_read(sess);
		if (rc <= 0) {
			sess->error(sess);
			return rc;
		}
	}
	if (what & OSMO_FD_WRITE) {
		int rc = tls_write(sess);
		if (rc < 0) {
			sess->error(sess);
			return rc;
		}
	}

	return 0;
}

static int load_keys(struct osmo_pcap_client_conn *conn)
{
	struct osmo_tls_session *sess = &conn->tls_session;
	gnutls_datum_t data;
	int rc;

	if (!conn->tls_client_cert || !conn->tls_client_key) {
		LOGP(DTLS, LOGL_DEBUG, "Skipping x509 client cert %p %p\n",
			conn->tls_client_cert, conn->tls_client_key);
		return 0;
	}


	rc = gnutls_load_file(conn->tls_client_cert, &data);
	if (rc < 0) {
		LOGP(DTLS, LOGL_ERROR, "Failed to load file=%s rc=%d\n",
			conn->tls_client_cert, rc);
		return -1;
	}
	rc = gnutls_pcert_import_x509_raw(&sess->pcert, &data, GNUTLS_X509_FMT_PEM, 0);
	gnutls_free(data.data);
	if (rc < 0) {
		LOGP(DTLS, LOGL_ERROR, "Failed to import file=%s rc=%d\n",
			conn->tls_client_cert, rc);
		return -1;
	}
	sess->pcert_alloc = true;

	/* copied to RAM.. nothing we can do about it */
	rc = gnutls_load_file(conn->tls_client_key, &data);
	if (rc < 0) {
		LOGP(DTLS, LOGL_ERROR, "Failed to load file=%s rc=%d\n",
			conn->tls_client_key, rc);
		return -1;
	}
	gnutls_privkey_init(&sess->privk);
	rc = gnutls_privkey_import_x509_raw(sess->privk, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
	gnutls_free(data.data);
	if (rc < 0) {
		LOGP(DTLS, LOGL_ERROR, "Failed to load file=%s rc=%d\n",
			conn->tls_client_key, rc);
		release_keys(sess);
		return -1;
	}
	sess->privk_alloc = true;
	return 0;
}

size_t osmo_tls_pending(struct osmo_tls_session *sess)
{
	return gnutls_record_check_pending(sess->session);
}

bool osmo_tls_init_server_session(struct osmo_pcap_conn *conn,
					struct osmo_pcap_server *server)
{
	struct osmo_tls_session *sess = &conn->tls_session;
	struct osmo_wqueue *wq = &conn->rem_wq;
	int rc;

	gnutls_global_set_log_level(server->tls_log_level);

	memset(sess, 0, sizeof(*sess));
	sess->in_use = sess->anon_alloc = sess->cert_alloc = false;
	rc = gnutls_init(&sess->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "gnutls_init failed with rc=%d\n", rc);
		return false;
	}
	gnutls_session_set_ptr(sess->session, sess);
	sess->in_use = true;

	/* use default or string */
	if (server->tls_priority) {
		const char *err;
		rc = gnutls_priority_set_direct(sess->session, server->tls_priority, &err);
	} else {
		rc = gnutls_set_default_priority(sess->session);
	}

	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "def prio failed with rc=%d\n", rc);
		osmo_tls_release(sess);
		return false;
	}

	/* allow username/password operation */
	rc = gnutls_anon_allocate_server_credentials(&sess->anon_serv_cred);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "Failed to allocate anon cred rc=%d\n", rc);
		osmo_tls_release(sess);
		return false;
	}
	sess->anon_serv_alloc = true;

	/* x509 certificate handling */
	rc = gnutls_certificate_allocate_credentials(&sess->cert_cred);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "Failed to allocate x509 cred rc=%d\n", rc);
		osmo_tls_release(sess);
		return false;
	}
	sess->cert_alloc = true;

	/* set the credentials now */
	if (server->dh_params_allocated) {
		gnutls_anon_set_server_dh_params(sess->anon_serv_cred, server->dh_params);
		gnutls_certificate_set_dh_params(sess->cert_cred, server->dh_params);
	}

	if (server->tls_allow_anon)
		gnutls_credentials_set(sess->session, GNUTLS_CRD_ANON, sess->anon_serv_cred);
	if (server->tls_allow_x509)
		gnutls_credentials_set(sess->session, GNUTLS_CRD_CERTIFICATE, sess->cert_cred);

	if (server->tls_capath) {
		rc = gnutls_certificate_set_x509_trust_file(
				sess->cert_cred, server->tls_capath, GNUTLS_X509_FMT_PEM);
		if (rc != GNUTLS_E_SUCCESS) {
			LOGP(DTLS, LOGL_ERROR, "Failed to load capath from path=%s rc=%d\n",
				server->tls_capath, rc);
			osmo_tls_release(sess);
			return false;
		}
	}

	if (server->tls_crlfile) {
		rc = gnutls_certificate_set_x509_crl_file(
				sess->cert_cred, server->tls_crlfile, GNUTLS_X509_FMT_PEM);
		if (rc != GNUTLS_E_SUCCESS) {
			LOGP(DTLS, LOGL_ERROR, "Failed to load crlfile from path=%s rc=%d\n",
				server->tls_crlfile, rc);
			osmo_tls_release(sess);
			return false;
		}
	}

	if (server->tls_server_cert && server->tls_server_key) {
		rc = gnutls_certificate_set_x509_key_file(
				sess->cert_cred, server->tls_server_cert, server->tls_server_key,
				GNUTLS_X509_FMT_PEM);
		if (rc != GNUTLS_E_SUCCESS) {
			LOGP(DTLS, LOGL_ERROR, "Failed to load crt/key from path=%s/%s rc=%d\n",
				server->tls_server_cert, server->tls_server_key, rc);
			osmo_tls_release(sess);
			return false;
		}
	}

	#warning "TODO client certificates"

	gnutls_transport_set_int(sess->session, wq->bfd.fd);
	gnutls_handshake_set_timeout(sess->session,
					GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	osmo_fd_setup(&wq->bfd, wq->bfd.fd, OSMO_FD_READ | OSMO_FD_WRITE, osmo_tls_client_bfd_cb, sess, 0);
	sess->need_handshake = true;
	sess->wqueue = wq;
	return true;
}

bool osmo_tls_init_client_session(struct osmo_pcap_client_conn *client)
{
	struct osmo_tls_session *sess = &client->tls_session;
	struct osmo_wqueue *wq = &client->wqueue;
	unsigned int status;
	int rc;

	gnutls_global_set_log_level(client->tls_log_level);

	memset(sess, 0, sizeof(*sess));
	sess->in_use = sess->anon_alloc = sess->cert_alloc = false;
	rc = gnutls_init(&sess->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "gnutls_init failed with rc=%d\n", rc);
		return false;
	}
	gnutls_session_set_ptr(sess->session, sess);
	sess->in_use = true;

	/* use default or string */
	if (client->tls_priority) {
		const char *err;
		rc = gnutls_priority_set_direct(sess->session, client->tls_priority, &err);
	} else {
		rc = gnutls_set_default_priority(sess->session);
	}

	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "def prio failed with rc=%d\n", rc);
		osmo_tls_release(sess);
		return false;
	}

	/* allow username/password operation */
	rc = gnutls_anon_allocate_client_credentials(&sess->anon_cred);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "Failed to allocate anon cred rc=%d\n", rc);
		osmo_tls_release(sess);
		return false;
	}
	sess->anon_alloc = true;

	/* x509 certificate handling */
        rc = gnutls_certificate_allocate_credentials(&sess->cert_cred);
	if (rc != GNUTLS_E_SUCCESS) {
		LOGP(DTLS, LOGL_ERROR, "Failed to allocate x509 cred rc=%d\n", rc);
		osmo_tls_release(sess);
		return false;
	}
	sess->cert_alloc = true;

	/* set the credentials now */
	gnutls_credentials_set(sess->session, GNUTLS_CRD_ANON, sess->anon_cred);
	gnutls_credentials_set(sess->session, GNUTLS_CRD_CERTIFICATE, sess->cert_cred);

	if (client->tls_capath) {
		rc = gnutls_certificate_set_x509_trust_file(
				sess->cert_cred, client->tls_capath, GNUTLS_X509_FMT_PEM);
		if (rc != GNUTLS_E_SUCCESS) {
			LOGP(DTLS, LOGL_ERROR, "Failed to load capath from path=%s rc=%d\n",
				client->tls_capath, rc);
			osmo_tls_release(sess);
			return false;
		}
	}

	if (load_keys(client) != 0) {
		osmo_tls_release(sess);
		return false;
	}

	gnutls_certificate_set_retrieve_function2(sess->cert_cred, cert_callback);

	/* set the hostname if we have one */
	if (client->tls_hostname)
		gnutls_server_name_set(sess->session, GNUTLS_NAME_DNS,
				client->tls_hostname, strlen(client->tls_hostname));

	/* do the verification */
	if (client->tls_verify) {
		gnutls_certificate_set_verify_function(sess->cert_cred, verify_cert_cb);
		gnutls_certificate_verify_peers3(sess->session, client->tls_hostname, &status);
	} else
		LOGP(DTLS, LOGL_NOTICE, "Not going to validate certs as configured\n");

	gnutls_transport_set_int(sess->session, wq->bfd.fd);
	gnutls_handshake_set_timeout(sess->session,
					GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	osmo_fd_setup(&wq->bfd, wq->bfd.fd, OSMO_FD_READ | OSMO_FD_WRITE, osmo_tls_client_bfd_cb, sess, 0);
	sess->need_handshake = true;
	sess->wqueue = wq;
	return true;
}

void osmo_tls_release(struct osmo_tls_session *session)
{
	if (!session->in_use)
		return;

	gnutls_deinit(session->session);

	release_keys(session);

	if (session->anon_alloc)
		gnutls_anon_free_client_credentials(session->anon_cred);
	if (session->anon_serv_alloc)
		gnutls_anon_free_server_credentials(session->anon_serv_cred);
	if (session->cert_alloc)
		gnutls_certificate_free_credentials(session->cert_cred);
	session->in_use = false;
}
