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

#include <stdlib.h>


#define PCAP_STRING	"PCAP related functions\n"
#define SERVER_STRING	"Server string\n"

static struct cmd_node client_node = {
	CLIENT_NODE,
	"%s(client)#",
	1,
};

DEFUN(cfg_client,
      cfg_client_cmd,
      "client",
      "Enter the client configuration\n")
{
	vty->node = CLIENT_NODE;
	return CMD_SUCCESS;
}

static int config_write_client(struct vty *vty)
{
	vty_out(vty, "client%s", VTY_NEWLINE);

	if (pcap_client->device)
		vty_out(vty, " pcap device %s%s",
			pcap_client->device, VTY_NEWLINE);

	if (pcap_client->filter_string)
		vty_out(vty, " pcap filter %s%s",
			pcap_client->filter_string, VTY_NEWLINE);
	vty_out(vty, " pcap detect-loop %d%s",
		pcap_client->filter_itself, VTY_NEWLINE);

	if (pcap_client->srv_ip)
		vty_out(vty, " server ip %s%s",
			pcap_client->srv_ip, VTY_NEWLINE);

	if (pcap_client->srv_port > 0)
		vty_out(vty, " server port %d%s",
			pcap_client->srv_port, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_client_device,
      cfg_client_device_cmd,
      "pcap device NAME",
      PCAP_STRING "the device to filter\n" "device name\n")
{
	osmo_client_capture(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_client_filter,
      cfg_client_filter_cmd,
      "pcap filter .NAME",
      PCAP_STRING "filter string in pcap syntax\n" "filter\n")
{
	char *filter = argv_concat(argv, argc, 0);
	if (!filter) {
		vty_out(vty, "Failed to allocate buffer.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}


	if (osmo_client_filter(pcap_client, filter) != 0) {
		vty_out(vty, "Failed to set the device.%s", VTY_NEWLINE);
		talloc_free(filter);
		return CMD_WARNING;
	}

	talloc_free(filter);
	return CMD_SUCCESS;
}

DEFUN(cfg_client_loop,
      cfg_client_loop_cmd,
      "pcap detect-loop (0|1)",
      PCAP_STRING "detect loop and drop\n" "No detection\n" "Detection\n")
{
	pcap_client->filter_itself = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_server_ip,
      cfg_server_ip_cmd,
      "server ip A.B.C.D",
      SERVER_STRING "IP Address of the server\n" "IP\n")
{
	talloc_free(pcap_client->srv_ip);
	pcap_client->srv_ip = talloc_strdup(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_server_port,
      cfg_server_port_cmd,
      "server port <1-65535>",
      SERVER_STRING "Port\n" "Number\n")
{
	pcap_client->srv_port = atoi(argv[0]);
	return CMD_SUCCESS;
}


int vty_client_init(struct osmo_pcap_client *pcap)
{
	install_element(CONFIG_NODE, &cfg_client_cmd);
	install_node(&client_node, config_write_client);
	install_default(CLIENT_NODE);

	install_element(CLIENT_NODE, &cfg_client_device_cmd);
	install_element(CLIENT_NODE, &cfg_client_filter_cmd);
	install_element(CLIENT_NODE, &cfg_client_loop_cmd);

	install_element(CLIENT_NODE, &cfg_server_ip_cmd);
	install_element(CLIENT_NODE, &cfg_server_port_cmd);

	return 0;
}
