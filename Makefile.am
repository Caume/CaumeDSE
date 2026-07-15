SUBDIRS = .
AM_CFLAGS = @GENERAL_CFLAGS@ @ADDITIONAL_CFLAGS@ @HARDEN_CFLAGS@
AM_LDFLAGS = @PERL_LDOPTS@ @HARDEN_LDFLAGS@
ACLOCAL_AMFLAGS = -I m4 -I m4.local
AUTOMAKE_OPTIONS = subdir-objects

spath = @SECUREDIR@
tdbpath = @TESTDB@
tpath = @TESTFILES@
ipath = @PREFIX@
ipathbindir = @BINDIR@
ipathdatadir = @DATADIR@

ipathbin_PROGRAMS = CaumeDSE CaumeDSE-debug-tests
caume_common_sources = common.h config.c crypto.c crypto.h db.c db.h engine_admin.c engine_admin.h engine_interface.c engine_interface.h filehandling.c filehandling.h function_tests.c function_tests.h perl_interpreter.c perl_interpreter.h runtime.c runtime.h strhandling.c strhandling.h webservice_interface.c webservice_interface.h xs_init.c
CaumeDSE_SOURCES = main.c $(caume_common_sources)
CaumeDSE_debug_tests_SOURCES = debug_tests.c $(caume_common_sources)
ipathdata_DATA = favicon.ico TEST/testCertAuth/ca.pem TEST/testCertAuth/server.pem TEST/testCertAuth/server.key
EXTRA_DIST = TEST README-alpha CHANGELOG.md README.md TUTORIAL.md API_EXAMPLES.md AI_USAGE.md openapi.yaml

xs_init.c:
	`@PERL@ -MExtUtils::Embed -e xsinit -- -o xs_init.c`

clean-local:
	rm -rf xs_init.c

install-data-local:
	if [ ! -z "$(tpath)" ] ; then \
		$(MKDIR_P) "$(tpath)" && cp -R TEST/testfiles/* "$(tpath)" ; \
	fi
	if [ ! -z "$(spath)" ] ; then \
		$(MKDIR_P) "$(spath)" && chmod 700 "$(spath)" ; \
	fi
	if [ ! -z "$(tdbpath)" ] ; then \
		cp -R TEST/testDB_opt_cdse/* "$(tdbpath)" ; \
	fi
uninstall-local:
	if [ -d "$(spath)" ] ; then \
		rm -rf "$(spath)" ; \
	fi
	if [ -d "$(tpath)" ] ; then \
		rm -rf "$(tpath)" ; \
	fi
