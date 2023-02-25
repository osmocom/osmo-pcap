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

#include <osmo-pcap/common.h>
#include <osmo-pcap/osmo_pcap_client.h>
#include <osmo-pcap/osmo_tls.h>

#include <osmocom/core/application.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/talloc.h>

#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "osmopcapconfig.h"

static const char *config_file = "osmo-pcap-client.cfg";
static int daemonize = 0;

void *tall_cli_ctx;
struct osmo_pcap_client *pcap_client;
extern void *tall_msgb_ctx;
extern void *tall_ctr_ctx;


static const struct rate_ctr_desc pcap_client_ctr_desc[] = {
	[CLIENT_CTR_CONNECT]		= { "server:connect",		"Connects to the server" },
	[CLIENT_CTR_BYTES]		= { "captured:bytes",		"Captured bytes        " },
	[CLIENT_CTR_PKTS]		= { "captured:pkts",		"Captured packets      " },
	[CLIENT_CTR_2BIG]		= { "bpf:too_big",		"Captured data too big " },
	[CLIENT_CTR_NOMEM]		= { "client:no_mem",		"No memory available   " },
	[CLIENT_CTR_QERR]		= { "client:queue_err",		"Can not queue data    " },
	[CLIENT_CTR_PERR]		= { "client:pcap_err",		"libpcap error         " },
	[CLIENT_CTR_WERR]		= { "client:write_err",		"Write error           " },
	[CLIENT_CTR_P_RECV]		= { "pcap:recv",		"PCAP received packets " },
	[CLIENT_CTR_P_DROP]		= { "pcap:drop",		"PCAP dropped packets  " },
	[CLIENT_CTR_P_IFDROP]		= { "pcap:ifdrop",		"iface dropped packets " },
};

static const struct rate_ctr_group_desc pcap_client_ctr_group_desc = {
	.group_name_prefix		= "pcap:client",
	.group_description		= "PCAP Client statistics",
	.num_ctr			= ARRAY_SIZE(pcap_client_ctr_desc),
	.ctr_desc			= pcap_client_ctr_desc,
	.class_id			= OSMO_STATS_CLASS_GLOBAL,
};

static struct vty_app_info vty_info = {
	.name		= "OsmoPCAPClient",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= osmopcap_go_parent,
	.is_config_node	= osmopcap_is_config_node,
};

static void print_usage()
{
	printf("Usage: osmo_pcap_client\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -V --version Print the version number\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp. Print a timestamp in the debug output.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
	printf("  -c --config-file filename The config file to use.\n");

	printf("\nVTY reference generation:\n");
	printf("     --vty-ref-mode MODE     VTY reference generation mode (e.g. 'expert').\n");
	printf("     --vty-ref-xml           Generate the VTY reference XML output and exit.\n");
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;
	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation "
				"mode '%s'\n", prog_name, optarg);
			exit(2);
		}
		break;
	case 2:
		fprintf(stderr, "Generating the VTY reference in mode '%s' (%s)\n",
			get_value_string(vty_ref_gen_mode_names, vty_ref_mode),
			get_value_string(vty_ref_gen_mode_desc, vty_ref_mode));
		vty_dump_xml_ref_mode(stdout, (enum vty_ref_gen_mode) vty_ref_mode);
		exit(0);
	default:
		fprintf(stderr, "%s: error parsing cmdline options\n", prog_name);
		exit(2);
	}
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static int long_option = 0;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"daemonize", 0, 0, 'D'},
			{"debug", 1, 0, 'd'},
			{"version", 0, 0, 'V'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"log-level", 1, 0, 'e'},
			{"config-file", 1, 0, 'c'},
			{"vty-ref-mode", 1, &long_option, 1},
			{"vty-ref-xml", 0, &long_option, 2},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:DsTc:e:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 0:
			handle_long_options(argv[0], long_option);
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		default:
			/* ignore */
			break;
		}
	}
}

static void signal_handler(int signum)
{
	fprintf(stdout, "signal %u received\n", signum);

	switch (signum) {
	case SIGINT:
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report and
		 * then run default SIGABRT handler, who will generate coredump
		 * and abort the process. abort() should do this for us after we
		 * return, but program wouldn't exit if an external SIGABRT is
		 * received.
		 */
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_cli_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_cli_ctx, stderr);
		break;
	default:
		break;
	}
}

static void talloc_init_ctx()
{
	tall_cli_ctx = talloc_named_const(NULL, 0, "client");
	tall_msgb_ctx = talloc_named_const(tall_cli_ctx, 0, "msgb");
	tall_ctr_ctx = talloc_named_const(tall_cli_ctx, 0, "counter");
}

int main(int argc, char **argv)
{
	int rc;

	talloc_init_ctx();
	osmo_init_logging2(tall_cli_ctx, &log_info);

	vty_info.copyright = osmopcap_copyright;
	vty_info.tall_ctx = tall_cli_ctx;
	vty_init(&vty_info);
	logging_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	vty_client_init();

	/* parse options */
	handle_options(argc, argv);

	rate_ctr_init(tall_cli_ctx);
	osmo_stats_init(tall_cli_ctx);

	/* seed the PRNG */
	srand(time(NULL));


	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	osmo_init_ignore_signals();

	osmo_tls_init();

	pcap_client = osmo_pcap_client_alloc(tall_cli_ctx);
	if (!pcap_client) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate osmo_pcap_client.\n");
		exit(1);
	}

	/* initialize the queue */
	INIT_LLIST_HEAD(&pcap_client->conns);
	osmo_client_conn_init(&pcap_client->conn, pcap_client);
	pcap_client->conn.name = "default";

	/* initialize the stats interface */
	pcap_client->ctrg = rate_ctr_group_alloc(pcap_client, &pcap_client_ctr_group_desc, 0);
	if (!pcap_client->ctrg) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to allocate rate ctr\n");
		exit(1);
	}

	if (vty_read_config_file(config_file, NULL) < 0) {
		LOGP(DCLIENT, LOGL_ERROR,
		     "Failed to parse the config file: %s\n", config_file);
		exit(1);
	}

	rc = telnet_init_default(tall_cli_ctx, NULL, OSMO_VTY_PORT_PCAP_CLIENT);
	if (rc < 0) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to bind telnet interface\n");
		exit(1);
	}


	/* attempt to connect to the remote */
	if (pcap_client->conn.srv_ip && pcap_client->conn.srv_port > 0)
		osmo_client_connect(&pcap_client->conn);

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		osmo_select_main(0);
	}

	return(0);
}
