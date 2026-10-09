SUBDIRS = .
AM_CPPFLAGS = @HERRADURAKEX_CPPFLAGS@
AM_CFLAGS = @GENERAL_CFLAGS@ @ADDITIONAL_CFLAGS@ @HARDEN_CFLAGS@ @SANITIZER_CFLAGS@
AM_LDFLAGS = @PERL_LDOPTS@ @HARDEN_LDFLAGS@ @SANITIZER_LDFLAGS@
ACLOCAL_AMFLAGS = -I m4 -I m4.local
AUTOMAKE_OPTIONS = subdir-objects

spath = @SECUREDIR@
tdbpath = @TESTDB@
tpath = @TESTFILES@
ipath = @PREFIX@
ipathbindir = @BINDIR@
ipathdatadir = @DATADIR@

ipathbin_PROGRAMS = CaumeDSE CaumeDSE-debug-tests caumedse-admin
caume_common_sources = common.h config.c crypto.c crypto.h context_registry.c context_registry.h context_manager.c context_manager.h db.c db.h engine_admin.c engine_admin.h engine_interface.c engine_interface.h filehandling.c filehandling.h function_tests.c function_tests.h perl_interpreter.c perl_interpreter.h runtime.c runtime.h strhandling.c strhandling.h webservice_interface.c webservice_interface.h xs_init.c
CaumeDSE_SOURCES = main.c $(caume_common_sources)
CaumeDSE_debug_tests_SOURCES = debug_tests.c $(caume_common_sources)
caumedse_admin_SOURCES = admin.c admin.h storage_migration.c $(caume_common_sources)
check_PROGRAMS = reprotect-fixture context-registry-fixture context-manager-fixture
context_manager_fixture_SOURCES = context_manager_fixture.c context_manager.c context_manager.h context_registry.c context_registry.h
context_manager_fixture_CPPFLAGS = $(AM_CPPFLAGS) -DCDSE_CONTEXT_MANAGER_TESTING
context_registry_fixture_SOURCES = context_registry_fixture.c context_registry.c context_registry.h
reprotect_fixture_SOURCES = reprotect_fixture.c $(caume_common_sources)
TESTS = test_reprotect_cli.sh test_storage_migration.sh test_sample_test_manager.sh test_context_registry.sh test_context_manager.sh
TESTS_ENVIRONMENT = srcdir='$(srcdir)'
ipathdata_DATA = favicon.ico TEST/testCertAuth/ca.pem TEST/testCertAuth/server.pem TEST/testCertAuth/server.key
EXTRA_DIST = $(TESTS) TEST samples favicon.ico CHANGELOG.md README.md TUTORIAL.md API_EXAMPLES.md AI_USAGE.md HERRADURAKEX_AT_REST_PLAN.md openapi.yaml herradura_compat.h

xs_init.c:
	`@PERL@ -MExtUtils::Embed -e xsinit -- -o xs_init.c`

clean-local:
	rm -rf xs_init.c

install-data-local:
	if [ ! -z "$(tpath)" ] ; then \
		$(MKDIR_P) "$(DESTDIR)$(tpath)" && cp -R TEST/testfiles/* "$(DESTDIR)$(tpath)" ; \
	fi
	if [ ! -z "$(spath)" ] ; then \
		$(MKDIR_P) "$(DESTDIR)$(spath)" && chmod 700 "$(DESTDIR)$(spath)" ; \
	fi
	if [ ! -z "$(tdbpath)" ] ; then \
		cp -R TEST/testDB_opt_cdse/* "$(DESTDIR)$(tdbpath)" ; \
	fi
uninstall-local:
	if [ -d "$(DESTDIR)$(spath)" ] ; then \
		rm -rf "$(DESTDIR)$(spath)" ; \
	fi
	if [ ! -z "$(tpath)" ] && [ -d "$(DESTDIR)$(tpath)" ] ; then \
		rm -rf "$(DESTDIR)$(tpath)" ; \
	fi
