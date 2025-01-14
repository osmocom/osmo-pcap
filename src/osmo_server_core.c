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

void osmo_pcap_conn_event(struct osmo_pcap_conn *conn,
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

static void zmq_send_client_data(struct osmo_pcap_conn *conn,
				 const uint8_t *data, size_t len)
{
	char *event_name;

	if (!conn->server->zmq_publ)
		return;

	/*
	 * This multi-part support is insane... so if we lose the first
	 * or the last part of the multipart message stuff is going out
	 * of sync. *great* As we can't do anything about it right now
	 * just close the eyes and send it.
	 */
	event_name = talloc_asprintf(conn, "data.v1.%s", conn->name);
	pcap_zmq_send(conn->server->zmq_publ, event_name, strlen(event_name), ZMQ_SNDMORE);
	talloc_free(event_name);

	pcap_zmq_send(conn->server->zmq_publ,
			conn->file_hdr, conn->file_hdr_len,
			ZMQ_SNDMORE);
	pcap_zmq_send(conn->server->zmq_publ,
			data, len,
			0);
}

static inline size_t calc_data_max_len(const struct osmo_pcap_server *server)
{
	size_t data_max_len;

	/* Some safe value regarding variable size options in a given pcapng block... */
	const size_t pcapng_max_len_opt = 4096;
	const size_t pcapng_max_iface_len = 256;

	/* Maximum of the 2 types of .pcap blocks: */
	data_max_len = OSMO_MAX(sizeof(struct pcap_file_header),
				sizeof(struct osmo_pcap_pkthdr) + server->max_snaplen);

	/* pcapng SHB: */
	const size_t pcapng_shb_max_len = sizeof(struct pcapng_block_header) +
					  sizeof(struct pcapng_section_header_block) +
					  pcapng_max_len_opt +
					  sizeof(uint32_t);
	/* pcapng IDB: */
	const size_t pcapng_idb_max_len = sizeof(struct pcapng_block_header) +
					  sizeof(struct pcapng_iface_descr_block) +
					  pcapng_max_len_opt +
					  sizeof(uint32_t);
	/* hdr_link for pcapng (SHB + N*IDB) */
	const size_t pcapg_hdr_link_max_len = pcapng_shb_max_len + // SHB
					      (pcapng_max_iface_len * pcapng_idb_max_len); // N * IDB
	data_max_len = OSMO_MAX(data_max_len, pcapg_hdr_link_max_len);

	/* pcapng EPB: */
	const size_t pcapng_epb_max_len = sizeof(struct pcapng_block_header) +
					  sizeof(struct pcapng_enhanced_packet_block) +
					  pcapng_max_len_opt +
					  sizeof(uint32_t);
	data_max_len = OSMO_MAX(data_max_len, pcapng_epb_max_len + server->max_snaplen);
	return data_max_len;
}

static struct osmo_pcap_conn *osmo_pcap_conn_alloc(struct osmo_pcap_server *server,
						   const char *name)
{
	struct osmo_pcap_conn *conn;
	struct rate_ctr_group_desc *desc;

	conn = talloc_zero(server, struct osmo_pcap_conn);
	if (!conn) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Failed to allocate the connection peer=%s.\n", name);
		return NULL;
	}

	conn->data_max_len = calc_data_max_len(server);
	conn->data = talloc_zero_size(conn, sizeof(struct osmo_pcap_data) + conn->data_max_len);
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

struct osmo_pcap_conn *osmo_pcap_server_find_or_create(
				struct osmo_pcap_server *server,
				const char *name)
{
	struct osmo_pcap_conn *conn;

	llist_for_each_entry(conn, &server->conn, entry) {
		if (strcmp(conn->name, name) == 0)
			return conn;
	}
	return osmo_pcap_conn_alloc(server, name);
}

void osmo_pcap_conn_free(struct osmo_pcap_conn *conn)
{
	osmo_pcap_conn_close(conn);
	llist_del(&conn->entry);
	talloc_free(conn);
}

/* Move pcap file from base_path to completed_path, and updates
 * conn->curr_filename to point to new location. */
void move_completed_trace_if_needed(struct osmo_pcap_conn *conn)
{
	struct osmo_pcap_server *server = conn->server;
	char *curr_filename_cpy_bname = NULL;
	char *curr_filename_cpy_dname = NULL;
	char *bname = NULL;
	char *curr_dirname = NULL;
	char *new_dirname = NULL;
	char *new_filename = NULL;
	size_t new_filename_len;
	int rc;

	if (!conn->curr_filename)
		return;

	if (!server->completed_path)
		return;

	/* Assumption: curr_filename is canonical absolute pathname. */

	/* basename and dirname may modify input param, and return a string
	 * which shall not be freed, potentially pointing to the input param. */
	curr_filename_cpy_dname = talloc_strdup(conn, conn->curr_filename);
	curr_filename_cpy_bname = talloc_strdup(conn, conn->curr_filename);
	if (!curr_filename_cpy_dname || !curr_filename_cpy_bname)
		goto ret_free1;

	curr_dirname = dirname(curr_filename_cpy_dname);
	bname = basename(curr_filename_cpy_bname);
	if (!curr_dirname || !bname) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to resolve dirname and basename for '%s'\n",
		     conn->curr_filename);
		goto ret_free1;
	}

	new_dirname = realpath(server->completed_path, NULL);
	if (!new_dirname) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to resolve path '%s': %s\n",
		     server->completed_path, strerror(errno));
		goto ret_free1;
	}

	new_filename_len = strlen(new_dirname) + 1 /* '/' */ + strlen(bname) + 1 /* '\0' */;
	new_filename = talloc_size(conn, new_filename_len);
	if (!new_filename)
		goto ret_free1;
	rc = snprintf(new_filename, new_filename_len, "%s/%s", new_dirname, bname);
	if (rc != new_filename_len - 1)
		goto ret_free2;

	LOGP(DSERVER, LOGL_INFO, "Moving completed pcap file '%s' -> '%s'\n", conn->curr_filename, new_filename);
	rc = rename(conn->curr_filename, new_filename);
	if (rc == -1) {
		int err = errno;
		LOGP(DSERVER, LOGL_ERROR, "Failed moving completed pcap file '%s' -> '%s': %s\n",
		     conn->curr_filename, new_filename, strerror(err));
		if (err == EXDEV)
			LOGP(DSERVER, LOGL_ERROR, "Fix your config! %s and %s shall not be in different filesystems!\n",
			     curr_dirname, new_dirname);
		goto ret_free2;
	}

	/* Now replace conn->curr_filename with new path: */
	talloc_free(conn->curr_filename);
	conn->curr_filename = new_filename;
	/* new_filename has been assigned, so we don't want to free it, hence move to ret_free1: */
	goto ret_free1;

ret_free2:
	talloc_free(new_filename);
ret_free1:
	free(new_dirname);
	talloc_free(curr_filename_cpy_bname);
	talloc_free(curr_filename_cpy_dname);
}

static void close_local_fd(struct osmo_pcap_conn *conn)
{
	close(conn->local_fd);
	conn->local_fd = -1;
	conn->wr_offset = 0;
}

void osmo_pcap_conn_close_trace(struct osmo_pcap_conn *conn)
{
	if (conn->local_fd >= 0)
		close_local_fd(conn);

	move_completed_trace_if_needed(conn);

	if (conn->curr_filename) {
		osmo_pcap_conn_event(conn, "closingtracefile", conn->curr_filename);
		rate_ctr_inc2(conn->ctrg, PEER_CTR_PROTATE);
		rate_ctr_inc2(conn->server->ctrg, SERVER_CTR_PROTATE);
		talloc_free(conn->curr_filename);
		conn->curr_filename = NULL;
	}
}

void osmo_pcap_conn_close(struct osmo_pcap_conn *conn)
{
	if (conn->rem_wq.bfd.fd >= 0) {
		osmo_fd_unregister(&conn->rem_wq.bfd);
		close(conn->rem_wq.bfd.fd);
		conn->rem_wq.bfd.fd = -1;
		osmo_tls_release(&conn->tls_session);
	}
	TALLOC_FREE(conn->file_hdr);
	conn->file_hdr_len = 0;

	osmo_pcap_conn_close_trace(conn);
	osmo_pcap_conn_event(conn, "disconnect", NULL);
}

/* Update conn->last_write if needed. This field is used to keep the last time
 * period where we wrote to the pcap file. Once a new write period (based on
 * rotation VTY config) is detected, the pcap file we write to is rotated. */
static void update_last_write(struct osmo_pcap_conn *conn, time_t now, size_t len)
{
	time_t last = mktime(&conn->last_write);

	/* Skip time udpates if wall clock went backwards (ie. due to drift
	 * correction or DST). As a result, time rotation checks will skip
	 * opening a new pcap file with an older timestamp, and instead keep
	 * using the current one. */
	if (now > last)
		localtime_r(&now, &conn->last_write);

	conn->wr_offset += len;
}

void osmo_pcap_conn_restart_trace(struct osmo_pcap_conn *conn)
{
	time_t now = time(NULL);
	struct tm tm;
	int rc;
	char *real_base_path;

	osmo_pcap_conn_close_trace(conn);

	/* omit any storing/creation of the file */
	if (!conn->store) {
		update_last_write(conn, now, 0);
		talloc_free(conn->curr_filename);
		conn->curr_filename = NULL;
		return;
	}

	localtime_r(&now, &tm);
	real_base_path = realpath(conn->server->base_path, NULL);
	if (!real_base_path) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to resolve real path '%s': %s\n",
		     conn->server->base_path, strerror(errno));
		return;
	}
	conn->curr_filename = talloc_asprintf(conn, "%s/trace-%s-%d%.2d%.2d_%.2d%.2d%.2d.%s",
					      real_base_path, conn->name,
					      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
					      tm.tm_hour, tm.tm_min, tm.tm_sec,
					      conn->file_fmt == OSMO_PCAP_FMT_PCAP ? "pcap" : "pcapng");
	free(real_base_path);
	if (!conn->curr_filename) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to assemble filename for %s.\n", conn->name);
		return;
	}

	conn->local_fd = creat(conn->curr_filename, conn->server->permission_mask);
	if (conn->local_fd < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to create file '%s': %s\n",
		     conn->curr_filename, strerror(errno));
		return;
	}
	conn->wr_offset = 0;

	rc = write(conn->local_fd, conn->file_hdr, conn->file_hdr_len);
	if (rc != conn->file_hdr_len) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to write the header: %d\n", errno);
		close_local_fd(conn);
		return;
	}
	update_last_write(conn, now, rc);
}

void osmo_pcap_server_reopen(struct osmo_pcap_server *server)
{
	struct osmo_pcap_conn *conn;
	LOGP(DSERVER, LOGL_INFO, "Reopening all logfiles.\n");
	llist_for_each_entry(conn, &server->conn, entry) {
		/* Write the complete packet out first */
		if (conn->state == STATE_INITIAL) {
			osmo_pcap_conn_restart_trace(conn);
		} else {
			LOGP(DSERVER, LOGL_INFO, "Delaying %s until current packet is complete.\n", conn->name);
			conn->reopen_delayed = true;
		}
	}
}

/* Returns true if pcap was re-opened */
static bool check_restart_pcap_max_size(struct osmo_pcap_conn *conn, size_t data_len)
{
	if (!pcap_server->max_size_enabled)
		return false;
	if (conn->wr_offset + data_len <= conn->server->max_size)
		return false;

	LOGP(DSERVER, LOGL_NOTICE, "Rolling over file for %s (max-size)\n", conn->name);
	osmo_pcap_conn_restart_trace(conn);
	return true;
}

/* Checks if we are in a new record period since last time we wrote to a pcap, to know (return true)
 * whether a new pcap file needs to be opened. It calculates period based on intv and mod.
 * NOTE: Kept non-static to be able to validate it with unit tests. */
bool check_localtime(const struct tm *last_write, const struct tm *tm, enum time_interval intv, unsigned int mod)
{
	unsigned long long last_start, current_start;

	switch (intv) {
	case TIME_INTERVAL_SEC:
		if (last_write->tm_sec == tm->tm_sec &&
		    last_write->tm_min == tm->tm_min &&
		    last_write->tm_hour == tm->tm_hour &&
		    last_write->tm_mday == tm->tm_mday &&
		    last_write->tm_mon == tm->tm_mon &&
		    last_write->tm_year == tm->tm_year)
			return false;
		/* If minute/hour/day/month/year changed (passed through second 0), always rotate: */
		if (last_write->tm_min < tm->tm_min ||
		    last_write->tm_hour < tm->tm_hour ||
		    last_write->tm_mday < tm->tm_mday ||
		    last_write->tm_mon < tm->tm_mon ||
		    last_write->tm_year < tm->tm_year)
			return true;
		/* Same minute/hour/day/month/year, second changed. Check if we are still in same period: */
		last_start = last_write->tm_sec - (last_write->tm_sec % mod);
		current_start = tm->tm_sec - (tm->tm_sec % mod);
		if (current_start <= last_start)
			return false;
		return true;
	case TIME_INTERVAL_MIN:
		if (last_write->tm_min == tm->tm_min &&
		    last_write->tm_hour == tm->tm_hour &&
		    last_write->tm_mday == tm->tm_mday &&
		    last_write->tm_mon == tm->tm_mon &&
		    last_write->tm_year == tm->tm_year)
			return false;
		/* If hour/day/month/year changed (passed through minute 0), always rotate: */
		if (last_write->tm_hour < tm->tm_hour ||
		    last_write->tm_mday < tm->tm_mday ||
		    last_write->tm_mon < tm->tm_mon ||
		    last_write->tm_year < tm->tm_year)
			return true;
		/* Same hour/day/month/year, minute changed. Check if we are still in same period: */
		last_start = last_write->tm_min - (last_write->tm_min % mod);
		current_start = tm->tm_min - (tm->tm_min % mod);
		if (current_start <= last_start)
			return false;
		return true;
	case TIME_INTERVAL_HOUR:
		if (last_write->tm_hour == tm->tm_hour &&
		    last_write->tm_mday == tm->tm_mday &&
		    last_write->tm_mon == tm->tm_mon &&
		    last_write->tm_year == tm->tm_year)
			return false;
		/* If day/month/year changed (passed through hour 0), always rotate: */
		if (last_write->tm_mday < tm->tm_mday ||
		    last_write->tm_mon < tm->tm_mon ||
		    last_write->tm_year < tm->tm_year)
			return true;
		/* Same day/month/year, hour changed. Check if we are still in same period: */
		last_start = last_write->tm_hour - (last_write->tm_hour % mod);
		current_start = tm->tm_hour - (tm->tm_hour % mod);
		if (current_start <= last_start)
			return false;
		return true;
	case TIME_INTERVAL_DAY:
		if (last_write->tm_mday == tm->tm_mday &&
		    last_write->tm_mon == tm->tm_mon &&
		    last_write->tm_year == tm->tm_year)
			return false;
		/* If month/year changed (passed through day 1), always rotate: */
		if (last_write->tm_mon < tm->tm_mon ||
		    last_write->tm_year < tm->tm_year)
			return true;
		/* Same month/year, day changed. Check if we are still in same period: */
		/* Note: tm_mday is [1, 31], hence the -1 below: */
		last_start = (last_write->tm_mday - 1) - ((last_write->tm_mday - 1) % mod);
		current_start = (tm->tm_mday - 1) - ((tm->tm_mday - 1) % mod);
		if (current_start <= last_start)
			return false;
		return true;
	case TIME_INTERVAL_MONTH:
		if (last_write->tm_mon == tm->tm_mon &&
		    last_write->tm_year == tm->tm_year)
			return false;
		/* If year changed (passed through month 1), always rotate: */
		if (last_write->tm_year < tm->tm_year)
			return true;
		/* Same year, month changed. Check if we are still in same period: */
		last_start = last_write->tm_mon - (last_write->tm_mon % mod);
		current_start = tm->tm_mon - (tm->tm_mon % mod);
		if (current_start <= last_start)
			return false;
		return true;
	case TIME_INTERVAL_YEAR:
		/* Year changed. Check if we are still in same period: */
		last_start = last_write->tm_year - (last_write->tm_year % mod);
		current_start = tm->tm_year - (tm->tm_year % mod);
		if (current_start <= last_start)
			return false;
		return true;
	default:
		OSMO_ASSERT(false);
	}
}

static bool check_restart_pcap_localtime(struct osmo_pcap_conn *conn, time_t now)
{
	struct tm tm;
	if (!pcap_server->rotate_localtime.enabled)
		return false;

	localtime_r(&now, &tm);
	if (!check_localtime(&conn->last_write, &tm,
			     pcap_server->rotate_localtime.intv,
			     pcap_server->rotate_localtime.modulus))
		return false;
	LOGP(DSERVER, LOGL_NOTICE, "Rolling over file for %s (localtime)\n", conn->name);
	osmo_pcap_conn_restart_trace(conn);
	return true;
}

/* New recorded packet is received.
 * Returns 0 on success, negative on error. */
int osmo_pcap_conn_process_data(struct osmo_pcap_conn *conn, const uint8_t *data, size_t len)
{
	time_t now = time(NULL);
	int rc;

	zmq_send_client_data(conn, data, len);

	if (!conn->store) {
		update_last_write(conn, now, 0);
		return 0;
	}

	if (conn->local_fd < -1) {
		LOGP(DSERVER, LOGL_ERROR, "No file is open. close connection.\n");
		return -1;
	}

	/* Check if we are past the limit or on a day change. */
	if (!check_restart_pcap_max_size(conn, len))
		check_restart_pcap_localtime(conn, now);

	rc = write(conn->local_fd, data, len);
	if (rc != len) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to write for %s\n", conn->name);
		return -1;
	}
	update_last_write(conn, now, rc);
	return 0;
}

struct osmo_pcap_server *osmo_pcap_server_alloc(void *ctx)
{
	struct osmo_pcap_server *psrv = talloc_zero(ctx, struct osmo_pcap_server);
	OSMO_ASSERT(psrv);

	psrv->ctrg = rate_ctr_group_alloc(psrv, &pcap_server_group_desc, 0);
	OSMO_ASSERT(psrv->ctrg);

	INIT_LLIST_HEAD(&psrv->conn);
	psrv->base_path = talloc_strdup(psrv, "./");
	OSMO_ASSERT(psrv->base_path);
	psrv->permission_mask = 0440;
	psrv->max_size = 1073741824; /* 1024^3, 1GB **/
	psrv->max_size_enabled = true;
	psrv->max_snaplen = DEFAULT_SNAPLEN;
	/* By default rotate daily: */
	psrv->rotate_localtime.enabled = true;
	psrv->rotate_localtime.intv = TIME_INTERVAL_DAY;
	psrv->rotate_localtime.modulus = 1;
	return psrv;
}

void osmo_pcap_server_free(struct osmo_pcap_server *psrv)
{
	struct osmo_pcap_conn *conn;

	if (!psrv)
		return;

	while ((conn = llist_first_entry_or_null(&psrv->conn, struct osmo_pcap_conn, entry)))
		osmo_pcap_conn_free(conn);

	rate_ctr_group_free(psrv->ctrg);
	talloc_free(psrv);
}
