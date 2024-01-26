AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

SUBDIRS = include src contrib doc tests

BUILT_SOURCES = $(top_srcdir)/.version
EXTRA_DIST = \
	     .version \
	     README.md \
	     contrib/osmo-pcap.spec.in \
	     debian \
	     git-version-gen \
	     $(NULL)

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)


@RELMAKE@

$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
