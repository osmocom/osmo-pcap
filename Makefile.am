AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

SUBDIRS = include src contrib tests

BUILT_SOURCES = $(top_srcdir)/.version
EXTRA_DIST = git-version-gen .version

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)


@RELMAKE@

$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
