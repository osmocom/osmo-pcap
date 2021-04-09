EXTRA_DIST = vty

if BUILD_MANUALS
  # This is a significantly modified, multi-target adopted copy of
  # $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc
  VARIANTS = client server
  include $(srcdir)/vty/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-pcap
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
