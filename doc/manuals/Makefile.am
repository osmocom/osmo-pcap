EXTRA_DIST = osmopcap-usermanual.adoc \
    osmopcap-usermanual-docinfo.xml \
    chapters \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmopcap-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  # This is a significantly modified, multi-target adopted copy of
  # $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc
  VARIANTS = client server
  include $(srcdir)/vty/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-pcap
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
