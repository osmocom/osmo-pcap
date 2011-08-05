/*
 * osmo-pcap-client code
 *
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <osmo-pcap/osmo_pcap_client.h>
#include <osmo-pcap/common.h>

#include <osmocore/talloc.h>

#include <limits.h>

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif


static int pcap_read_cb(struct bsc_fd *fd, unsigned int what)
{
	struct osmo_pcap_client *client = fd->data;
	struct pcap_pkthdr hdr;
	const u_char *data;

	data = pcap_next(client->handle, &hdr);
	if (!data)
		return -1;

	osmo_client_send_data(client, &hdr, data);
	return 0;
}

static int osmo_install_filter(struct osmo_pcap_client *client)
{
	int rc;
	pcap_freecode(&client->bpf);

	if (!client->handle) {
		LOGP(DCLIENT, LOGL_NOTICE,
		    "Filter will only be applied later.\n");
		return 1;
	}

	rc = pcap_compile(client->handle, &client->bpf,
			  client->filter_string, 1, PCAP_NETMASK_UNKNOWN);
	if (rc != 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to compile the filter: %s\n",
		     pcap_geterr(client->handle));
		return rc;
	}

	rc = pcap_setfilter(client->handle, &client->bpf);
	if (rc != 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to set the filter on the interface: %s\n",
		     pcap_geterr(client->handle));
		pcap_freecode(&client->bpf);
		return rc;
	}

	return rc;
}

static void free_all(struct osmo_pcap_client *client)
{
	if (!client->handle)
		return;

	pcap_freecode(&client->bpf);

	if (client->fd.fd >= 0) {
		bsc_unregister_fd(&client->fd);
		client->fd.fd = -1;
	}

	pcap_close(client->handle);
	client->handle = NULL;
}

int osmo_client_capture(struct osmo_pcap_client *client, const char *device)
{
	int fd;

	talloc_free(client->device);
	free_all(client);

	client->device = talloc_strdup(client, device);
	if (!client->device) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to copy string.\n");
		return 1;
	}

	client->handle = pcap_open_live(client->device, 2000, 0,
					1000, client->errbuf);
	if (!client->handle) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to open the device: %s\n", client->errbuf);
		return 2;
	}

	fd = pcap_fileno(client->handle);
	if (fd == -1) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "No file descriptor provided.\n");
		free_all(client);
		return 3;
	}

	client->fd.fd = fd;
	client->fd.when = BSC_FD_READ;
	client->fd.cb = pcap_read_cb;
	client->fd.data = client;
	if (bsc_register_fd(&client->fd) != 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to register the fd.\n");
		client->fd.fd = -1;
		free_all(client);
		return 4;
	}

	osmo_client_send_link(client);

	if (client->filter_string) {
		osmo_install_filter(client);
	}

	return 0;
}

int osmo_client_filter(struct osmo_pcap_client *client, const char *filter)
{
	talloc_free(client->filter_string);
	client->filter_string = talloc_strdup(client, filter);
	return osmo_install_filter(client);
}
