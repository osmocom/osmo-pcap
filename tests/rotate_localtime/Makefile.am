AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOGB_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(PCAP_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(NULL)

AM_LDFLAGS = -no-install

EXTRA_DIST = \
	rotate_localtime_test.ok \
	rotate_localtime_test.err \
	$(NULL)

check_PROGRAMS = \
	rotate_localtime_test \
	$(NULL)

rotate_localtime_test_SOURCES = \
	rotate_localtime_test.c \
	$(NULL)

rotate_localtime_test_LDADD = \
	$(top_builddir)/src/osmo_server_network.o \
	$(top_builddir)/src/osmo_server_stats.o \
	$(top_builddir)/src/osmo_tls.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(LIBZMQ_LIBS) \
	$(NULL)


.PHONY: update_exp
update_exp:
	$(builddir)/rotate_localtime_test >$(srcdir)/rotate_localtime_test.ok 2>$(srcdir)/rotate_localtime_test.err
