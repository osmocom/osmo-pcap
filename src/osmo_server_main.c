/*
 * osmo-pcap-server code
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
#include <osmo-pcap/osmo_pcap_server.h>
#include <osmo-pcap/osmo_tls.h>

#include <osmocom/core/application.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/stats.h>

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "osmopcapconfig.h"

static const char *config_file = "osmo-pcap-server.cfg";
static int daemonize = 0;

void *tall_srv_ctx;
struct osmo_pcap_server *pcap_server;
extern void *tall_msgb_ctx;
extern void *tall_ctr_ctx;


static const struct rate_ctr_desc pcap_peer_ctr_desc[] = {
	[PEER_CTR_CONNECT]		= { "peer:connect",	"Connect of a peer   " },
	[PEER_CTR_BYTES]		= { "peer:bytes",	"Received bytes      " },
	[PEER_CTR_PKTS]			= { "peer:pkts",	"Received packets    " },
	[PEER_CTR_PROTATE]		= { "peer:file_rotated","Capture file rotated" },
};

static const struct rate_ctr_desc pcap_server_ctr_desc[] = {
	[SERVER_CTR_CONNECT]		= { "server:connect",	"Connect of a peer   " },
	[SERVER_CTR_BYTES]		= { "server:bytes",	"Received bytes      " },
	[SERVER_CTR_PKTS]		= { "server:pkts",	"Received packets    " },
	[SERVER_CTR_PROTATE]		= { "server:file_rotated", "Capture file rotated" },
	[SERVER_CTR_NOCLIENT]		= { "server:no_client", "Unknown connected   " },
};

const struct rate_ctr_group_desc pcap_peer_group_desc = {
	.group_name_prefix		= NULL,	/* will be dynamically patched */
	.group_description		= "PCAP peer statistics",
	.num_ctr			= ARRAY_SIZE(pcap_peer_ctr_desc),
	.ctr_desc			= pcap_peer_ctr_desc,
	.class_id			= OSMO_STATS_CLASS_PEER,
};

static const struct rate_ctr_group_desc pcap_server_group_desc = {
	.group_name_prefix		= "pcap:server",
	.group_description		= "PCAP Server global statistics",
	.num_ctr			= ARRAY_SIZE(pcap_server_ctr_desc),
	.ctr_desc			= pcap_server_ctr_desc,
	.class_id			= OSMO_STATS_CLASS_GLOBAL,
};

static struct vty_app_info vty_info = {
	.name		= "OsmoPCAPServer",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= osmopcap_go_parent,
	.is_config_node	= osmopcap_is_config_node,
};

static void print_usage()
{
	printf("Usage: osmo_pcap_server\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp. Print a timestamp in the debug output.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
	printf("  -c --config-file filename The config file to use.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"daemonize", 0, 0, 'D'},
			{"debug", 1, 0, 'd'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"log-level", 1, 0, 'e'},
			{"config-file", 1, 0, 'c'},
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
		case 'D':
			daemonize = 1;
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
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
		talloc_report_full(tall_srv_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_srv_ctx, stderr);
		break;
	case SIGHUP:
		osmo_pcap_server_reopen(pcap_server);
		break;
	default:
		break;
	}
}

static void talloc_init_ctx()
{
	tall_srv_ctx = talloc_named_const(NULL, 0, "server");
	tall_msgb_ctx = talloc_named_const(tall_srv_ctx, 0, "msgb");
	tall_ctr_ctx = talloc_named_const(tall_srv_ctx, 0, "counter");
}

int main(int argc, char **argv)
{
	int rc;

	talloc_init_ctx();
	osmo_init_logging2(tall_srv_ctx, &log_info);

	vty_info.copyright = osmopcap_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds();
	osmo_stats_vty_add_cmds();

	/* parse options */
	handle_options(argc, argv);

	rate_ctr_init(tall_srv_ctx);
	osmo_stats_init(tall_srv_ctx);

	/* seed the PRNG */
	srand(time(NULL));

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	osmo_init_ignore_signals();
	signal(SIGHUP, &signal_handler);

	osmo_tls_init();

	rc = telnet_init(tall_srv_ctx, NULL, OSMO_VTY_PORT_PCAP_SERVER);
	if (rc < 0) {
		LOGP(DCLIENT, LOGL_ERROR, "Failed to bind telnet interface\n");
		exit(1);
	}

	pcap_server = talloc_zero(tall_srv_ctx, struct osmo_pcap_server);
	if (!pcap_server) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to allocate osmo_pcap_server.\n");
		exit(1);
	}
	pcap_server->ctrg = rate_ctr_group_alloc(pcap_server, &pcap_server_group_desc, 0);
	if (!pcap_server->ctrg) {
		LOGP(DSERVER, LOGL_ERROR, "Failed to allocate rate counter.\n");
		exit(1);
	}

	INIT_LLIST_HEAD(&pcap_server->conn);
	pcap_server->base_path = talloc_strdup(pcap_server, "./");
	pcap_server->max_size = 1073741824;
	pcap_server->max_snaplen = DEFAULT_SNAPLEN;
	vty_server_init(pcap_server);

	if (vty_read_config_file(config_file, NULL) < 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Failed to parse the config file: %s\n", config_file);
		exit(1);
	}

	osmo_tls_server_init(pcap_server);

	/* attempt to connect to the remote */
	if (osmo_pcap_server_listen(pcap_server) != 0) {
		LOGP(DSERVER, LOGL_ERROR,
		     "Failed to listen for incoming data\n");
		exit(1);
	}

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
