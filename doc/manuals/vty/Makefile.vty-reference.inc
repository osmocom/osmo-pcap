DOCBOOKS = $(foreach v,$(VARIANTS),vty/osmo-pcap-$(v)-vty-reference.xml)
DOCBOOKS_DEPS = $(DOCBOOKS) $(addsuffix .inc,$(DOCBOOKS))
INC_DIR = $(abspath $(builddir)/vty)

include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.docbook.inc

CLEAN_FILES += $(DOCBOOKS_DEPS)
CLEAN_FILES += $(addsuffix .inc.gen,$(DOCBOOKS))
CLEAN_FILES += $(addsuffix .inc.merged,$(DOCBOOKS))

$(INC_DIR):
	mkdir -p $@

vty/osmo-pcap-%-vty-reference.xml: $(top_builddir)/src/osmo-pcap-% $(INC_DIR)
	sed -e "s|@@GENERATED@@|$@.inc|" \
	    -e "s|@@VARIANT@@|$(notdir $<)|" \
	    -e "s|@@REV_NUMBER@@|$(VERSION)|" \
	    -e "s|@@REV_DATE@@|$(shell date +"%dth %B %Y")|" \
	    -e "s|@@CR_YEAR@@|$(shell date +"%Y")|" \
		$(srcdir)/vty/osmo-pcap-vty-reference.xml > $@

vty/osmo-pcap-%-vty-reference.xml.inc: $(top_builddir)/src/osmo-pcap-% \
				       $(OSMO_GSM_MANUALS_DIR)/common/vty_additions.xml \
				       $(OSMO_GSM_MANUALS_DIR)/common/chapters/vty.xml \
				       $(OSMO_GSM_MANUALS_DIR)/vty_reference.xsl \
				       $(srcdir)/vty/*.xml $(INC_DIR)
	# a) Invoke osmo-pcap-% to generate the list of commands first
	$< --vty-ref-mode default --vty-ref-xml > "$@.gen"
	# ... filter garbage potentially printed by libraries to stdout
	sed -i '/^<vtydoc/,$$!d' "$@.gen"
	# b) Merge the result of a) with global and local additions
	$(OSMO_GSM_MANUALS_DIR)/build/vty_reference_combine.sh \
		$(realpath $(OSMO_GSM_MANUALS_DIR)/merge_doc.xsl) "$@.gen" \
		$(OSMO_GSM_MANUALS_DIR)/common/vty_additions.xml \
		$(srcdir)/vty/vty_additions.xml > "$@.merged"
	# c) Convert the result of b) into a valid docbook
	xsltproc $(OSMO_GSM_MANUALS_DIR)/vty_reference.xsl "$@.merged" > $@
