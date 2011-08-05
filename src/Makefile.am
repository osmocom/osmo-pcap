INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)/
AM_CFLAGS = -Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(PCAP_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS)

bin_PROGRAMS = osmo_pcap_client

osmo_pcap_client_SOURCES = osmo_client_main.c osmo_common.c \
			   osmo_client_core.c osmo_client_vty.c \
			   osmo_client_network.c
osmo_pcap_client_LDADD = $(PCAP_LIBS)

#osmo_pcap_server_SOURCES = osmo_server_main.c osmo_common.c \
#			   osmo_server_vty.c osmo_server_network.c
