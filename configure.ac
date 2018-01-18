#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([CaumeDSE], [1.0.1], [0h3rr3r4@gmail.com])
AM_INIT_AUTOMAKE([dist-bzip2 color-tests readme-alpha 1.5])
AC_CONFIG_SRCDIR([function_tests.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_PROG_CC_C_O

PERL=''
AC_CHECK_PROG(PERL,perl,perl,[])
perl_version="5.10.0"
if test "x$PERL" != "x"; then
	AC_MSG_CHECKING(for perl version >= $perl_version)
	$PERL -e "use $perl_version;" > /dev/null 2>&1
	if test $? -ne 0; then
    		AC_MSG_RESULT(no);
  	else
    		AC_MSG_RESULT(ok);
  	fi
else
  	AC_MSG_WARN(could not find perl!)
fi

# Checks for libraries.
AC_MSG_NOTICE([ ----- Looking for required libraries -----])
# FIXME: Replace `main' with a function in `-lc':
AC_CHECK_LIB([c], [main], [], AC_MSG_ERROR([Library libc not found!]))
# FIXME: Replace `main' with a function in `-lcrypt':
AC_CHECK_LIB([crypt], [main], [], AC_MSG_ERROR([Library libcrypt not found!]))
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [main], [], AC_MSG_ERROR([Library libcrypto not found!]))
# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main], [], AC_MSG_ERROR([Library libdl not found!]))
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [main], [], AC_MSG_ERROR([Library libm not found!]))
# FIXME: Replace `main' with a function in `-lmicrohttpd':
AC_CHECK_LIB([microhttpd], [main], [], AC_MSG_ERROR([Library libmicrohttpd not found!]))
# FIXME: Replace `main' with a function in `-lnsl':
AC_CHECK_LIB([nsl], [main], [], AC_MSG_ERROR([Library libnsl not found!]))
# FIXME: Replace `main' with a function in `-lperl':
AC_CHECK_LIB([perl], [main], [], AC_MSG_ERROR([Library libperl not found!]))
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main], [], AC_MSG_ERROR([Library libpthread not found!]))
# FIXME: Replace `main' with a function in `-lutil':
AC_CHECK_LIB([util], [main], [], AC_MSG_ERROR([Library libutil not found!]))
# FIXME: Replace `main' with a function in `-lgnutls':
AC_CHECK_LIB([gnutls], [main], [], AC_MSG_ERROR([Library gnutls not found!]))

# Checks for header files.
AC_MSG_NOTICE([ ----- Looking for required C include files -----])
AC_CHECK_HEADERS([fcntl.h], [], AC_MSG_ERROR([Include file <fcntl.h> not found!]))
AC_CHECK_HEADERS([locale.h], [], AC_MSG_ERROR([Include file <locale.h> not found!])) 
AC_CHECK_HEADERS([stdint.h], [], AC_MSG_ERROR([Include file <stdint.h> not found!]))
AC_CHECK_HEADERS([stdlib.h], [], AC_MSG_ERROR([Include file <stdlib.h> not found!]))
AC_CHECK_HEADERS([string.h], [], AC_MSG_ERROR([Include file <string.h> not found!]))
AC_CHECK_HEADERS([sys/socket.h], [], AC_MSG_ERROR([Include file <sys/socket.h> not found!]))
AC_CHECK_HEADERS([sys/time.h], [], AC_MSG_ERROR([Include file <time.h> not found!]))
AC_CHECK_HEADERS([unistd.h], [], AC_MSG_ERROR([Include file <unistd.h> not found!]))
AC_CHECK_HEADERS([ctype.h], [], AC_MSG_ERROR([Include file <ctype.h> not found!]))
AC_CHECK_HEADERS([stdarg.h], [], AC_MSG_ERROR([Include file <stdarg.h> not found!]))
AC_CHECK_HEADERS([stdio.h], [], AC_MSG_ERROR([Include file <stdio.h> not found!]))
AC_CHECK_HEADERS([sys/types.h], [], AC_MSG_ERROR([Include file <sys/types.h> not found!]))
AC_CHECK_HEADERS([sys/stat.h], [], AC_MSG_ERROR([Include file <sys/stat.h> not found!]))
AC_CHECK_HEADERS([sys/select.h], [], AC_MSG_ERROR([Include file <sys/select.h> not found!]))

# Check for libmicrohttpd required headers
AC_MSG_NOTICE([ ----- Looking for required Libmicrohttpd include files -----])
AC_CHECK_HEADERS([microhttpd.h], [], AC_MSG_ERROR([Include file <microhttpd.h> not found!]))

# Check for OpenSSL required headers
AC_MSG_NOTICE([ ----- Looking for required OpenSSL include files -----])
AC_CHECK_HEADERS([openssl/bio.h], [], AC_MSG_ERROR([Include file <openssl/bio.h> not found!]))
AC_CHECK_HEADERS([openssl/err.h], [], AC_MSG_ERROR([Include file <openssl/err.h> not found!]))
AC_CHECK_HEADERS([openssl/rand.h], [], AC_MSG_ERROR([Include file <openssl/rand.h> not found!]))
AC_CHECK_HEADERS([openssl/bn.h], [], AC_MSG_ERROR([Include file <openssl/bn.h> not found!]))
AC_CHECK_HEADERS([openssl/hmac.h], [], AC_MSG_ERROR([Include file <openssl/hmac.h> not found!]))
AC_CHECK_HEADERS([openssl/evp.h], [], AC_MSG_ERROR([Include file <openssl/evp.h> not found!]))
AC_CHECK_HEADERS([openssl/buffer.h], [], AC_MSG_ERROR([Include file <openssl/buffer.h> not found!]))

# Check for GnuTLS system headers     
AC_MSG_NOTICE([ ----- Looking for required GnuTLS include files -----])
AC_CHECK_HEADERS([gnutls/gnutls.h], [], AC_MSG_ERROR([Include file <gnutls/gnutls.h> not found!]))
AC_CHECK_HEADERS([gnutls/x509.h], [], AC_MSG_ERROR([Include file <gnutls/x509.h> not found!]))

# Check for Perl embedded interpreter required headers
AC_MSG_NOTICE([ ----- Looking for required PERL interpreter include files -----])
PERL_INCLUDES=`$PERL -MExtUtils::Embed -e perl_inc`
oldCPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $PERL_INCLUDES"
AC_CHECK_HEADERS([EXTERN.h], [], AC_MSG_ERROR([Include file <EXTERN.h> not found!]))
AC_CHECK_HEADERS([perl.h], [], [AC_MSG_ERROR([Include file <perl.h> not found!]) enable_perl=no],
[#if HAVE_EXTERN_H
# include <EXTERN.h>
#endif])
AC_CHECK_HEADERS([XSUB.h], [], AC_MSG_ERROR([Include file <XSUB.h> not found!]))
CPPFLAGS="$oldCPPFLAGS"

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset setlocale strndup])

# --- Hardening section, based on http://mainisusuallyafunction.blogspot.mx/2012/05/automatic-binary-hardening-with.html by Keegan McAllister
#  We use the same hardening flags for C and C++. We must check that each flag
#  is supported by both compilers.
AC_DEFUN([check_cc_flag],
	[AX_CHECK_COMPILE_FLAG([$1], [$2], [$3], [-Werror $4])])
AC_DEFUN([check_link_flag],
	[AX_CHECK_LINK_FLAG([$1], [$2], [$3], [-Werror $4])])
AC_ARG_ENABLE([HARDENING],
	[  --disable-HARDENING			disable compiler and linker hardening paramters (for testing; NOT RECOMMENDED!)],
	[HARDEN="no"],
	[HARDEN="yes"])
HARDEN_CFLAGS=""
HARDEN_LDFLAGS=""
if test $HARDEN == 'yes' ; then
	AC_MSG_NOTICE([ ----- Looking for supported hardening parameters -----])
	check_cc_flag([-fwrapv], [HARDEN_CFLAGS="$HARDEN_CFLAGS -fwrapv"], [], [-fwrapv])
	check_cc_flag([-fno-strict-overflow], [HARDEN_CFLAGS="$HARDEN_CFLAGS -fno-strict-overflow"], [], [-fno-strict-overflow])
	check_cc_flag([-fno-strict-aliasing], [HARDEN_CFLAGS="$HARDEN_CFLAGS -fno-strict-aliasing"], [], [-fno-strict-aliasing])
	# This one will likely succeed, even on platforms where it does nothing.
	check_cc_flag([-D_FORTIFY_SOURCE=2], [HARDEN_CFLAGS="$HARDEN_CFLAGS -D_FORTIFY_SOURCE=2"], [], [-D_FORTIFY_SOURCE=2])                                    
	check_cc_flag([-fstack-protector-all],
		[check_link_flag([-fstack-protector-all], [HARDEN_CFLAGS="$HARDEN_CFLAGS -fstack-protector-all"
			check_cc_flag([-Wstack-protector], [HARDEN_CFLAGS="$HARDEN_CFLAGS -Wstack-protector"],
				[], [-fstack-protector-all])
		check_cc_flag([--param ssp-buffer-size=1], [HARDEN_CFLAGS="$HARDEN_CFLAGS --param ssp-buffer-size=1"],
		[], [-fstack-protector-all])])])
	# At the link step, we might want -pie (GCC) or -Wl,-pie (Clang on OS X)
	# The linker checks also compile code, so we need to include -fPIE as well.
	check_cc_flag([-fPIE],
		[check_link_flag([-fPIE -pie],
			[HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
			HARDEN_LDFLAGS="$HARDEN_LDFLAGS -pie"],
			[check_link_flag([-fPIE -Wl,-pie],
				[HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
				HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-pie"])])])
	check_link_flag([-Wl,-z,relro],
		[HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,relro"
	check_link_flag([-Wl,-z,now],
		[HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,now"])])
fi
AC_SUBST([HARDEN_CFLAGS])
AC_SUBST([HARDEN_LDFLAGS])
# --- End of hardening section

# Set default cflags for Makefile.am
GENERAL_CFLAGS="-DERROR_LOG -DPURIFY -DSQLITE_SECURE_DELETE -Wall `$PERL -MExtUtils::Embed -e ccopts --`"
RELEASE_CFLAGS="-s -DRELEASE"
DEBUG_CFLAGS="-g -DDEBUG"
AC_SUBST(GENERAL_CFLAGS)
AC_SUBST(PERL)

# Set default paths for installation
AC_SUBST([PREFIX])
if test $prefix == 'NONE' ; then
	PREFIX=/opt;
else
	PREFIX=$prefix;
fi
AC_SUBST([BINDIR], ["$PREFIX/cdse/bin"])
AC_SUBST([DATADIR], ["$PREFIX/cdse"])
AC_SUBST([SECUREDIR], ["$DATADIR/secureTmp"])
AC_ARG_ENABLE([DEBUG],
	[  --enable-DEBUG			enable DEBUG output to console (for testing; NOT RECOMMENDED!)],
	[ADDITIONAL_CFLAGS="$DEBUG_CFLAGS" compile_mode="DEBUG" TESTFILES="$DATADIR/testfiles"],
	[ADDITIONAL_CFLAGS="$RELEASE_CFLAGS" compile_mode="RELEASE" TESTFILES=''])
AC_SUBST(ADDITIONAL_CFLAGS)
AC_SUBST(TESTFILES)
AC_ARG_ENABLE([TESTDATABASE],
	[  --enable-TESTDATABASE			copy TEST DATABASE files to Data directory],
	[TESTDB="$DATADIR"],
	[TESTDB=''])
AC_SUBST(TESTDB)
AC_ARG_ENABLE([BYPASSTLSAUTHINHTTP],
	[  --enable-BYPASSTLSAUTHINHTTP		Accepts sessions in HTTP when TLS authentication is used (for testing; NOT RECOMMENDED!)],
	[BYTLS=1],
	[BYTLS=0])
AC_ARG_ENABLE([OLDPBKDF1],
	[  --enable-OLDPBKDF1			Uses PBKDF1 (i.e. PKCS5v1.5, compatible with openssl's command line tool) instead of PBKDF2 (for testing; NOT RECOMMENDED!)],
	[PBKDF=1],
	[PBKDF=2])

# Set required configuration defines y config.h
AC_DEFINE_UNQUOTED([PATH_DATADIR], ["$DATADIR"], [Path for default data and system databases.])
AC_DEFINE_UNQUOTED([BYPASS_TLS_IN_HTTP], [$BYTLS], [Enables (1) or disables (0) bypassing TLS authentication when it is required and protocol is not a TLS/HTTPS session (e.g. when testing HTTP)])
AC_DEFINE_UNQUOTED([PBKDF1_OPENSSL_CLI_COMPATIBILITY], [$PBKDF], [Enables (1) or disables (2) Use of old Password Based Key Derivation Function (PKCS5v1.5)])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo \
"-------------------------------------------------
 ${PACKAGE_NAME} Version ${PACKAGE_VERSION}
 Installation directories:
 	Prefix: 	'${PREFIX}'.
	Binaries: 	'${BINDIR}'.
	Data: 		'${DATADIR}'.
	Test files:	'${TESTFILES}'
	Test database: 	'${TESTDB}'
 Build parameters:
	Compiler: 	'${CC}'
	CPPFLAGS:	'${CPPFLAGS}'
	CFLAGS:		'${CFLAGS}'
	DEFAULT FLAGS: 	'${GENERAL_CFLAGS}'
	CUSTOM FLAGS	'${ADDITIONAL_CFLAGS}'
 Hardening parameters:
	Compiler:	'${HARDEN_CFLAGS}'
	Linker:		'${HARDEN_LDFLAGS}'
 Package features:
	Build mode: 	'${compile_mode}'

 Now type 'make @<:@<target>@:>@' where the optional <target> is:
     all                - build all binaries
     install            - install everything
--------------------------------------------------"

