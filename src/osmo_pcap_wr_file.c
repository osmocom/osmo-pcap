/*
 * Asynchronous non-blocking write to a file
 *
 * (C) 2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <inttypes.h>
#include <libgen.h>

#include <osmocom/core/talloc.h>
#include <osmo-pcap/common.h>
#include <osmo-pcap/osmo_pcap_server.h>

static void local_iofd_write_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
	struct osmo_pcap_wr_file *wrf = osmo_iofd_get_data(iofd);

	LOGP(DSERVER, LOGL_DEBUG, "%s,fd=%d,wr_completed=%zu: write_cb(res=%d)\n",
	     osmo_iofd_get_name(iofd), osmo_iofd_get_fd(iofd), (size_t)wrf->wr_completed, res);
	if (res <= 0) {
		LOGP(DSERVER, LOGL_ERROR, "%s,fd=%d,wr_completed=%zu: Failed writing: %s (%d)\n",
		     osmo_iofd_get_name(iofd), osmo_iofd_get_fd(iofd), (size_t)wrf->wr_completed,
		     strerror(-res), res);
		/* Trigger cb to tell user to free it, even if it was not being flushed.
		 * Special attention must be kept at the user regarding this code path, ie.
		 * user can't assume the wrf was actually in flushing state...
		 */
		if (wrf->flush_completed_cb)
			wrf->flush_completed_cb(wrf, wrf->data);
		/* wrf may be freed here. */
		return;
	}

	wrf->wr_completed += res;

	if (osmo_pcap_wr_file_is_flushing(wrf)) {
		if (!osmo_pcap_wr_file_has_pending_writes(wrf)) {
			LOGP(DSERVER, LOGL_DEBUG, "%s,fd=%d,wr_completed=%zu: closing now after completed data write\n",
			     osmo_iofd_get_name(iofd), osmo_iofd_get_fd(iofd), (size_t)wrf->wr_completed);
			if (wrf->flush_completed_cb)
				wrf->flush_completed_cb(wrf, wrf->data);
			/* wrf may be freed here. */
			return;
		}
	}
}

struct osmo_pcap_wr_file *osmo_pcap_wr_file_alloc(void *ctx, void *data)
{
	struct osmo_pcap_wr_file *wrf = talloc_zero(ctx, struct osmo_pcap_wr_file);
	OSMO_ASSERT(wrf);

	/* Initialize entry so that we can know whether we are included in a
	 * list in osmo_pcap_wr_file_is_flushing(): */
	INIT_LLIST_HEAD(&wrf->entry);
	wrf->data = data;
	wrf->wr_queue_max_length = PCAP_SERVER_FILE_WRQUEUE_MAX_LEN;
	wrf->wr_offset = 0;
	wrf->wr_completed = 0;

	return wrf;
}

void osmo_pcap_wr_file_free(struct osmo_pcap_wr_file *wrf)
{
	if (!wrf)
		return;
	osmo_pcap_wr_file_close(wrf);
	if (osmo_pcap_wr_file_is_flushing(wrf))
		llist_del(&wrf->entry);
	talloc_free(wrf);
}

void osmo_pcap_wr_file_set_flush_completed_cb(struct osmo_pcap_wr_file *wrf, osmo_pcap_wr_file_flush_completed_cb_t flush_completed_cb)
{
	wrf->flush_completed_cb = flush_completed_cb;
}

void osmo_pcap_wr_file_set_write_queue_max_length(struct osmo_pcap_wr_file *wrf, size_t max_len)
{
	wrf->wr_queue_max_length = max_len;
	if (wrf->local_iofd)
		osmo_iofd_set_txqueue_max_length(wrf->local_iofd, wrf->wr_queue_max_length);
}

int osmo_pcap_wr_file_open(struct osmo_pcap_wr_file *wrf, const char *filename, mode_t mode)
{
	struct osmo_io_ops ioops = {
		.read_cb = NULL,
		.write_cb = local_iofd_write_cb,
	};
	int rc;
	OSMO_ASSERT(filename);
	OSMO_ASSERT(wrf->local_iofd == NULL);

	rc = open(filename, O_CREAT|O_WRONLY|O_TRUNC|O_NONBLOCK, mode);
	if (rc < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to open file '%s': %s\n",
		     filename, strerror(errno));
		return rc;
	}

	wrf->local_iofd = osmo_iofd_setup(wrf, rc, filename, OSMO_IO_FD_MODE_READ_WRITE,
					  &ioops, wrf);
	if (!wrf->local_iofd)
		return -EBADFD;
	osmo_iofd_set_txqueue_max_length(wrf->local_iofd, wrf->wr_queue_max_length);
	if (osmo_iofd_register(wrf->local_iofd, -1) < 0) {
		osmo_iofd_free(wrf->local_iofd);
		wrf->local_iofd = NULL;
		return -ENAVAIL;
	}

	wrf->filename = talloc_strdup(wrf, filename);
	OSMO_ASSERT(wrf->filename);
	return rc;
}

void osmo_pcap_wr_file_close(struct osmo_pcap_wr_file *wrf)
{
	osmo_iofd_free(wrf->local_iofd);
	wrf->local_iofd = NULL;
}

int osmo_pcap_wr_file_write_msgb(struct osmo_pcap_wr_file *wrf, struct msgb *msg)
{
	int rc = osmo_iofd_write_msgb(wrf->local_iofd, msg);
	if (rc < 0)
		return rc;
	wrf->wr_offset += msgb_length(msg);
	return rc;
}

bool osmo_pcap_wr_file_has_pending_writes(const struct osmo_pcap_wr_file *wrf)
{
	return wrf->wr_completed < wrf->wr_offset;
}

/* Mark the wrf as done writing to it. It will be closed and freed
 * asynchronously when all data has been written to it.
 * wrf may be freed during the call to this function, so don't use it anymore. */
int osmo_pcap_wr_file_flush(struct osmo_pcap_wr_file *wrf, struct llist_head *wrf_flushing_list)
{
	if (osmo_pcap_wr_file_is_flushing(wrf)) {
		LOGP(DSERVER, LOGL_ERROR, "Trying to flush a file which was already being flushed: '%s'\n",
		     wrf->filename);
		return -EINVAL;
	}

	if (!osmo_pcap_wr_file_has_pending_writes(wrf)) {
		if (wrf->flush_completed_cb)
			wrf->flush_completed_cb(wrf, wrf->data);
		/* wrf may be freed here. */
		return 0;
	}

	/* Put it in the flushing list, it will be closed freed once pending writes complete. */
	llist_add_tail(&wrf->entry, wrf_flushing_list);
	return 0;
}

/* whether we finished pushing more data to the wrf and we are waiting for it to
 * finish writing before closing:
 */
bool osmo_pcap_wr_file_is_flushing(const struct osmo_pcap_wr_file *wrf)
{
	return !llist_empty(&wrf->entry);
}

/* Move file from current dir to dst_dirpath, and updates wrf->filename to point to new location. */
void osmo_pcap_wr_file_move_to_dir(struct osmo_pcap_wr_file *wrf, const char *dst_dirpath)
{
	char *curr_filename_cpy_bname = NULL;
	char *curr_filename_cpy_dname = NULL;
	char *bname = NULL;
	char *curr_dirname = NULL;
	char *new_dirname = NULL;
	char *new_filename = NULL;
	size_t new_filename_len;
	int rc;

	OSMO_ASSERT(wrf);
	OSMO_ASSERT(dst_dirpath);

	/* Assumption: curr_filename is canonical absolute pathname. */

	/* basename and dirname may modify input param, and return a string
	 * which shall not be freed, potentially pointing to the input param. */
	curr_filename_cpy_dname = talloc_strdup(wrf, wrf->filename);
	curr_filename_cpy_bname = talloc_strdup(wrf, wrf->filename);
	if (!curr_filename_cpy_dname || !curr_filename_cpy_bname)
		goto ret_free1;

	curr_dirname = dirname(curr_filename_cpy_dname);
	bname = basename(curr_filename_cpy_bname);
	if (!curr_dirname || !bname) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to resolve dirname and basename for '%s'\n",
		     wrf->filename);
		goto ret_free1;
	}

	new_dirname = realpath(dst_dirpath, NULL);
	if (!new_dirname) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to resolve path '%s': %s\n",
		     dst_dirpath, strerror(errno));
		goto ret_free1;
	}

	new_filename_len = strlen(new_dirname) + 1 /* '/' */ + strlen(bname) + 1 /* '\0' */;
	new_filename = talloc_size(wrf, new_filename_len);
	if (!new_filename)
		goto ret_free1;
	rc = snprintf(new_filename, new_filename_len, "%s/%s", new_dirname, bname);
	if (rc != new_filename_len - 1)
		goto ret_free2;

	LOGP(DSERVER, LOGL_INFO, "Moving completed pcap file '%s' -> '%s'\n", wrf->filename, new_filename);
	rc = rename(wrf->filename, new_filename);
	if (rc == -1) {
		int err = errno;
		LOGP(DSERVER, LOGL_ERROR, "Failed moving completed pcap file '%s' -> '%s': %s\n",
		     wrf->filename, new_filename, strerror(err));
		if (err == EXDEV)
			LOGP(DSERVER, LOGL_ERROR, "Fix your config! %s and %s shall not be in different filesystems!\n",
			     curr_dirname, new_dirname);
		goto ret_free2;
	}

	/* Now replace wrf->filename with new path: */
	talloc_free(wrf->filename);
	wrf->filename = new_filename;
	/* new_filename has been assigned, so we don't want to free it, hence move to ret_free1: */
	goto ret_free1;

ret_free2:
	talloc_free(new_filename);
ret_free1:
	free(new_dirname);
	talloc_free(curr_filename_cpy_bname);
	talloc_free(curr_filename_cpy_dname);
}
