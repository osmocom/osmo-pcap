AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)/
AM_CFLAGS = -Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOGB_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(PCAP_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-pcap-client \
	osmo-pcap-server \
	$(NULL)

osmo_pcap_client_SOURCES = \
	osmo_client_main.c \
	osmo_common.c \
	osmo_client_core.c \
	osmo_client_network.c \
	osmo_client_stats.c \
	osmo_client_vty.c \
	osmo_tls.c \
	$(NULL)

osmo_pcap_client_LDADD = \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(PCAP_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(NULL)

osmo_pcap_server_SOURCES = \
	osmo_server_main.c \
	osmo_common.c \
	osmo_server_vty.c \
	osmo_server_network.c \
	osmo_server_stats.c \
	osmo_tls.c \
	$(NULL)

osmo_pcap_server_LDADD = \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBZMQ_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(NULL)
