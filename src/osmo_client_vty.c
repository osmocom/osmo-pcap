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

#include <osmo-pcap/osmo_pcap_client.h>
#include <osmo-pcap/common.h>

#include <osmocom/core/talloc.h>

#include <stdlib.h>


#define PCAP_STRING	"PCAP related functions\n"
#define SERVER_STRING	"Server string\n"

static const struct value_string osmopcap_protocol_names[] = {
	{ PROTOCOL_OSMOPCAP,	"osmo-pcap" },
	{ PROTOCOL_IPIP,	"ipip" },
	{ 0, NULL }
};

static struct osmo_pcap_client_conn *get_conn(struct vty *vty)
{
	if (vty->node == CLIENT_NODE)
		return pcap_client->conn;
	return vty->index;
}

static struct cmd_node client_node = {
	CLIENT_NODE,
	"%s(client)# ",
	1,
};

static struct cmd_node server_node = {
	CLIENT_SERVER_NODE,
	"%s(server)# ",
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

static void write_client_conn_data(
			struct vty *vty,
			struct osmo_pcap_client_conn *conn,
			const char *indent)
{
	if (conn->tls_on) {
		vty_out(vty, "%s enable tls%s", indent, VTY_NEWLINE);
		vty_out(vty, "%s tls hostname %s%s", indent, conn->tls_hostname, VTY_NEWLINE);
		vty_out(vty, "%s %stls verify-cert%s", indent,
				conn->tls_verify ? "" : "no ", VTY_NEWLINE);
		if (conn->tls_capath)
			vty_out(vty, "%s tls capath %s%s", indent, conn->tls_capath, VTY_NEWLINE);
		if (conn->tls_client_cert)
			vty_out(vty, "%s tls client-cert %s%s", indent,
					conn->tls_client_cert, VTY_NEWLINE);
		if (conn->tls_client_key)
			vty_out(vty, "%s tls client-key %s%s", indent,
					conn->tls_client_key, VTY_NEWLINE);
		if (conn->tls_priority)
			vty_out(vty, "%s tls priority %s%s", indent,
					conn->tls_priority, VTY_NEWLINE);
		vty_out(vty, "%s tls log-level %d%s", indent,
			conn->tls_log_level, VTY_NEWLINE);
	}

	if (conn->srv_ip)
		vty_out(vty, "%s server ip %s%s", indent,
			conn->srv_ip, VTY_NEWLINE);

	if (conn->srv_port > 0)
		vty_out(vty, "%s server port %d%s", indent,
			conn->srv_port, VTY_NEWLINE);
	if (conn->source_ip)
		vty_out(vty, "%s source ip %s%s", indent,
			conn->source_ip, VTY_NEWLINE);

	if (conn->protocol != PROTOCOL_OSMOPCAP)
		vty_out(vty, "%s protocol %s%s", indent,
			get_value_string(osmopcap_protocol_names, conn->protocol), VTY_NEWLINE);

	if (conn->wqueue.max_length != WQUEUE_MAXLEN_DEFAULT)
		vty_out(vty, "%s wqueue max-length %u%s", indent,
			conn->wqueue.max_length, VTY_NEWLINE);
}

static int config_write_server(struct vty *vty)
{
	struct osmo_pcap_client_conn *conn;

	llist_for_each_entry(conn, &pcap_client->conns, entry) {
		if (conn == pcap_client->conn)
			continue;
		vty_out(vty, " pcap-store-connection %s%s", conn->name, VTY_NEWLINE);
		write_client_conn_data(vty, conn, " ");
		vty_out(vty, "  connect%s", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static int config_write_client(struct vty *vty)
{
	struct osmo_pcap_handle *ph;

	vty_out(vty, "client%s", VTY_NEWLINE);

	llist_for_each_entry(ph, &pcap_client->handles, entry) {
		vty_out(vty, " pcap device %s%s",
			ph->devname, VTY_NEWLINE);
	}
	if (pcap_client->snaplen != DEFAULT_SNAPLEN)
		vty_out(vty, " pcap snaplen %d%s",
			pcap_client->snaplen, VTY_NEWLINE);
	if (pcap_client->filter_string)
		vty_out(vty, " pcap filter %s%s",
			pcap_client->filter_string, VTY_NEWLINE);
	vty_out(vty, " pcap detect-loop %d%s",
		pcap_client->filter_itself, VTY_NEWLINE);
	if (pcap_client->gprs_filtering)
		vty_out(vty, " pcap add-filter gprs%s", VTY_NEWLINE);


	write_client_conn_data(vty, pcap_client->conn, "");
	return CMD_SUCCESS;
}

DEFUN(cfg_client_no_device,
      cfg_client_no_device_cmd,
      "no pcap device NAME",
      NO_STR PCAP_STRING "the device to filter\n" "device name\n")
{
	struct osmo_pcap_handle *ph = osmo_client_find_handle(pcap_client, argv[0]);
	if (!ph) {
		vty_out(vty, "%% Device %s not found!%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_pcap_handle_free(ph);
	return CMD_SUCCESS;
}

DEFUN(cfg_client_device,
      cfg_client_device_cmd,
      "pcap device NAME",
      PCAP_STRING "the device to filter\n" "device name\n")
{
	struct osmo_pcap_handle *ph = osmo_client_find_handle(pcap_client, argv[0]);
	if (!ph)
		osmo_pcap_handle_alloc(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_client_snaplen,
      cfg_client_snaplen_cmd,
	      "pcap snaplen <1-262144>", /* MAXIMUM_SNAPLEN */
      PCAP_STRING "snapshot length\n" "Bytes\n")
{
	pcap_client->snaplen = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_client_add_gprs,
      cfg_client_add_gprs_cmd,
      "pcap add-filter gprs",
      PCAP_STRING "Add-filter\n" "Custom filtering for GPRS\n")
{
	pcap_client->gprs_filtering = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_client_del_gprs,
      cfg_client_del_gprs_cmd,
      "no pcap add-filter gprs",
      NO_STR PCAP_STRING "Add-filter\n" "Custom filter for GPRS\n")
{
	pcap_client->gprs_filtering = 0;
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


#define TLS_STR "Transport Layer Security\n"

DEFUN(cfg_enable_tls,
      cfg_enable_tls_cmd,
      "enable tls",
      "Enable\n" "Transport Layer Security\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	if (!conn->tls_on) {
		if (conn->wqueue.bfd.fd >= 0)
			osmo_client_conn_reconnect(conn);
	}

	conn->tls_on = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_disable_tls,
      cfg_disable_tls_cmd,
      "disable tls",
      "Disable\n" "Transport Layer Security\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	if (conn->tls_on)
		osmo_client_conn_reconnect(conn);

	conn->tls_on = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_hostname,
      cfg_tls_hostname_cmd,
      "tls hostname NAME",
      TLS_STR "hostname for certificate validation\n" "name\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_hostname);
	conn->tls_hostname = talloc_strdup(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_hostname,
      cfg_no_tls_hostname_cmd,
      "no tls hostname",
      NO_STR TLS_STR "hostname for certificate validation\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_hostname);
	conn->tls_hostname = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_verify,
      cfg_tls_verify_cmd,
      "tls verify-cert",
      TLS_STR "Verify certificates\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	conn->tls_verify = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_verify,
      cfg_no_tls_verify_cmd,
      "no tls verify-cert",
      NO_STR TLS_STR "Verify certificates\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	conn->tls_verify = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_capath,
      cfg_tls_capath_cmd,
      "tls capath .PATH",
      TLS_STR "Trusted root certificates\n" "Filename\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_capath);
	conn->tls_capath = talloc_strdup(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_capath,
      cfg_no_tls_capath_cmd,
      "no tls capath",
      NO_STR TLS_STR "Trusted root certificates\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_capath);
	conn->tls_capath = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_client_cert,
      cfg_tls_client_cert_cmd,
      "tls client-cert .PATH",
      TLS_STR "Client certificate for authentication\n" "Filename\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_client_cert);
	conn->tls_client_cert = talloc_strdup(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_client_cert,
      cfg_no_tls_client_cert_cmd,
      "no tls client-cert",
      NO_STR TLS_STR "Client certificate for authentication\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_client_cert);
	conn->tls_client_cert = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_client_key,
      cfg_tls_client_key_cmd,
      "tls client-key .PATH",
      TLS_STR "Client private key\n" "Filename\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_client_key);
	conn->tls_client_key = talloc_strdup(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_client_key,
      cfg_no_tls_client_key_cmd,
      "no tls client-key",
      NO_STR TLS_STR "Client private key\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_client_key);
	conn->tls_client_key = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_priority,
      cfg_tls_priority_cmd,
      "tls priority STR",
      TLS_STR "Priority string for GNUtls\n" "Priority string\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_priority);
	conn->tls_priority = talloc_strdup(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_tls_priority,
      cfg_no_tls_priority_cmd,
      "no tls priority",
      NO_STR TLS_STR "Priority string for GNUtls\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->tls_priority);
	conn->tls_priority = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_tls_log_level,
      cfg_tls_log_level_cmd,
      "tls log-level <0-255>",
      TLS_STR "Log-level\n" "GNUtls debug level\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	conn->tls_log_level = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_server_ip,
      cfg_server_ip_cmd,
      "server ip A.B.C.D",
      SERVER_STRING "IP Address of the server\n" "IP\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->srv_ip);
	conn->srv_ip = talloc_strdup(pcap_client, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_server_port,
      cfg_server_port_cmd,
      "server port <1-65535>",
      SERVER_STRING "Port\n" "Number\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	conn->srv_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_source_ip,
      cfg_source_ip_cmd,
      "source ip A.B.C.D",
      SERVER_STRING "Source IP Address\n" "IP\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	talloc_free(conn->source_ip);
	conn->source_ip = talloc_strdup(pcap_client, argv[0]);
	return CMD_SUCCESS;
}


DEFUN(cfg_pcap_store,
      cfg_pcap_store_cmd,
      "pcap-store-connection .NAME",
      "Configure additional PCAP store server\n" "Name of server\n")
{
	struct osmo_pcap_client_conn *conn;
	conn = osmo_client_find_or_create_conn(pcap_client, argv[0]);
	if (!conn || conn == pcap_client->conn) {
		vty_out(vty, "%%Failed to find/create conection %s%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = conn;
	vty->node = CLIENT_SERVER_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_pcap_store,
      cfg_no_pcap_store_cmd,
      "no pcap-store-connection .NAME",
      NO_STR "Configure additional PCAP store server\n" "Name of server\n")
{
	struct osmo_pcap_client_conn *conn;
	conn = osmo_client_find_conn(pcap_client, argv[0]);
	if (!conn || conn == pcap_client->conn) {
		vty_out(vty, "%%Failed to find connection %s%ss",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_client_conn_free(conn);
	return CMD_SUCCESS;
}

DEFUN(cfg_client_connect,
      cfg_client_connect_cmd,
      "connect",
      "Connect to the storage\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	osmo_client_conn_connect(conn);
	return CMD_SUCCESS;
}

DEFUN(cfg_client_disconnect,
      cfg_client_disconnect_cmd,
      "disconnect",
      "Disconnect to the storage\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	osmo_client_conn_disconnect(conn);
	return CMD_SUCCESS;
}

#define PROTOCOL_STR "protocol (osmo-pcap|ipip)"
#define PROTOCOL_HELP "Configure the Protocol used for transfer\n" \
			"OsmoPCAP protocol (over TCP)\n" \
			"IPIP encapsulation (for real-time streaming to wireshark)\n"

DEFUN(cfg_protocol,
      cfg_protocol_cmd,
      PROTOCOL_STR,
      PROTOCOL_HELP)
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	conn->protocol = get_string_value(osmopcap_protocol_names, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_client_protocol,
      cfg_client_protocol_cmd,
      PROTOCOL_STR,
      PROTOCOL_HELP)
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	conn->protocol = get_string_value(osmopcap_protocol_names, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_wqueue_maxlength,
      cfg_wqueue_maxlength_cmd,
      "wqueue max-length <1-4294967295>",
      "Configure the write-queue used for transfer\n"
      "Configure the maximum amount of packets to be stored in the write-queue\n"
      "Maximum amount of packets before dropping starts\n")
{
	struct osmo_pcap_client_conn *conn = get_conn(vty);

	conn->wqueue.max_length = atoi(argv[0]);
	return CMD_SUCCESS;
}

int vty_client_init(void)
{
	install_element(CONFIG_NODE, &cfg_client_cmd);
	install_node(&client_node, config_write_client);

	install_node(&server_node, config_write_server);

	install_element(CLIENT_NODE, &cfg_client_no_device_cmd);
	install_element(CLIENT_NODE, &cfg_client_device_cmd);
	install_element(CLIENT_NODE, &cfg_client_snaplen_cmd);
	install_element(CLIENT_NODE, &cfg_client_filter_cmd);
	install_element(CLIENT_NODE, &cfg_client_loop_cmd);

	install_element(CLIENT_NODE, &cfg_server_ip_cmd);
	install_element(CLIENT_NODE, &cfg_server_port_cmd);
	install_element(CLIENT_NODE, &cfg_source_ip_cmd);
	install_element(CLIENT_NODE, &cfg_protocol_cmd);
	install_element(CLIENT_NODE, &cfg_wqueue_maxlength_cmd);

	install_element(CLIENT_NODE, &cfg_enable_tls_cmd);
	install_element(CLIENT_NODE, &cfg_disable_tls_cmd);
	install_element(CLIENT_NODE, &cfg_tls_hostname_cmd);
	install_element(CLIENT_NODE, &cfg_no_tls_hostname_cmd);
	install_element(CLIENT_NODE, &cfg_tls_verify_cmd);
	install_element(CLIENT_NODE, &cfg_no_tls_verify_cmd);
	install_element(CLIENT_NODE, &cfg_tls_capath_cmd);
	install_element(CLIENT_NODE, &cfg_no_tls_capath_cmd);
	install_element(CLIENT_NODE, &cfg_tls_client_cert_cmd);
	install_element(CLIENT_NODE, &cfg_no_tls_client_cert_cmd);
	install_element(CLIENT_NODE, &cfg_tls_client_key_cmd);
	install_element(CLIENT_NODE, &cfg_no_tls_client_key_cmd);
	install_element(CLIENT_NODE, &cfg_tls_priority_cmd);
	install_element(CLIENT_NODE, &cfg_no_tls_priority_cmd);
	install_element(CLIENT_NODE, &cfg_tls_log_level_cmd);

	install_element(CLIENT_NODE, &cfg_client_add_gprs_cmd);
	install_element(CLIENT_NODE, &cfg_client_del_gprs_cmd);


	/* per server confiug*/
	install_element(CLIENT_NODE, &cfg_pcap_store_cmd);
	install_element(CLIENT_NODE, &cfg_no_pcap_store_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_server_ip_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_server_port_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_source_ip_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_enable_tls_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_disable_tls_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_tls_hostname_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_no_tls_hostname_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_tls_verify_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_no_tls_verify_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_tls_capath_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_no_tls_capath_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_tls_client_cert_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_no_tls_client_cert_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_tls_client_key_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_no_tls_client_key_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_tls_priority_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_no_tls_priority_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_tls_log_level_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_client_connect_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_client_disconnect_cmd);
	install_element(CLIENT_SERVER_NODE, &cfg_client_protocol_cmd);

	return 0;
}
