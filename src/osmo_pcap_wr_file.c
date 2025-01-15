/*
 * Write to a file
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

struct osmo_pcap_wr_file *osmo_pcap_wr_file_alloc(void *ctx, void *data)
{
	struct osmo_pcap_wr_file *wrf = talloc_zero(ctx, struct osmo_pcap_wr_file);
	OSMO_ASSERT(wrf);

	wrf->data = data;
	wrf->local_fd = -1;
	wrf->wr_offset = 0;

	return wrf;
}

void osmo_pcap_wr_file_free(struct osmo_pcap_wr_file *wrf)
{
	if (!wrf)
		return;
	osmo_pcap_wr_file_close(wrf);
	talloc_free(wrf);
}

int osmo_pcap_wr_file_open(struct osmo_pcap_wr_file *wrf, const char *filename, mode_t mode)
{
	int rc;
	OSMO_ASSERT(filename);
	OSMO_ASSERT(wrf->local_fd == -1);

	rc = open(filename, O_CREAT|O_WRONLY|O_TRUNC, mode);
	if (rc < 0) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to open file '%s': %s\n",
		     filename, strerror(errno));
		return rc;
	}
	wrf->local_fd = rc;
	wrf->filename = talloc_strdup(wrf, filename);
	OSMO_ASSERT(wrf->filename);
	return rc;
}

void osmo_pcap_wr_file_close(struct osmo_pcap_wr_file *wrf)
{
	if (wrf->local_fd > 0) {
		close(wrf->local_fd);
		wrf->local_fd = -1;
	}
}

int osmo_pcap_wr_file_write(struct osmo_pcap_wr_file *wrf, const uint8_t *data, size_t len)
{
	int rc = write(wrf->local_fd, data, len);
	if (rc >= 0) {
		wrf->wr_offset += rc;
		if (rc != len) {
			LOGP(DSERVER, LOGL_ERROR, "Short write '%s': ret %d != %zu\n",
			     wrf->filename, rc, len);
			return -1;
		}
	}
	return rc;
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
