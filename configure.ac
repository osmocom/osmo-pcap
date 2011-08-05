dnl Process this file with autoconf to produce a configure script
AC_INIT([osmo-pcap],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc-devel@lists.openbsc.org])

AM_INIT_AUTOMAKE([dist-bzip2])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB

dnl checks for libraries
PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore < 0.2.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty < 0.2.0)

dnl checks for header files
AC_HEADER_STDC


dnl Checks for typedefs, structures and compiler characteristics
AC_ARG_WITH([pcap-config],
	AC_HELP_STRING([--with-pcap-config=FILE], [Use given pcap-config]),
	[pcapcfg="$withval" ],
	[AC_PATH_PROG([pcapcfg], [pcap-config], [])])
if test x$pcapcfg = "x"; then
	AC_MSG_ERROR([pcap-config can not be found])
fi

PCAP_LIBS=`$pcapcfg --libs`
PCAP_CFLAGS=`$pcapcfg --cflags`
AC_SUBST([PCAP_LIBS])
AC_SUBST([PCAP_CFLAGS])

# Coverage build taken from WebKit's configure.in
AC_MSG_CHECKING([whether to enable code coverage support])
AC_ARG_ENABLE(coverage,
              AC_HELP_STRING([--enable-coverage],
                             [enable code coverage support [default=no]]),
              [],[enable_coverage="no"])
AC_MSG_RESULT([$enable_coverage])
if test "$enable_coverage" = "yes"; then
   COVERAGE_CFLAGS="-ftest-coverage -fprofile-arcs"
   COVERAGE_LDFLAGS="-ftest-coverage -fprofile-arcs"
   AC_SUBST([COVERAGE_CFLAGS])
   AC_SUBST([COVERAGE_LDFLAGS])
fi

AM_CONFIG_HEADER(osmopcapconfig.h)

dnl Generate the output
AC_OUTPUT(
    include/Makefile
    include/osmo-pcap/Makefile
    src/Makefile
    contrib/Makefile
    Makefile)
