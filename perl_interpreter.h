/***
Copyright 2010-2018 by Omar Alejandro Herrera Reyna

    Caume Data Security Engine, also known as CaumeDSE is released under the
    GNU General Public License by the Copyright holder, with the additional
    exemption that compiling, linking, and/or using OpenSSL is allowed.

    LICENSE

    This file is part of Caume Data Security Engine, also called CaumeDSE.

    CaumeDSE is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CaumeDSE is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CaumeDSE.  If not, see <http://www.gnu.org/licenses/>.

    INCLUDED SOFTWARE

    This product includes software developed by the OpenSSL Project
    for use in the OpenSSL Toolkit (http://www.openssl.org/).
    This product includes cryptographic software written by
    Eric Young (eay@cryptsoft.com).
    This product includes software written by
    Tim Hudson (tjh@cryptsoft.com).

    This product includes software from the SQLite library that is in
    the public domain (http://www.sqlite.org/copyright.html).

    This product includes software from the GNU Libmicrohttpd project, Copyright
    © 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
    2008, 2009, 2010 , 2011, 2012 Free Software Foundation, Inc.

    This product includes software from Perl5, which is Copyright (C) 1993-2005,
    by Larry Wall and others.

***/
#ifndef PERL_INTERPRETER_H_INCLUDED
#define PERL_INTERPRETER_H_INCLUDED

// Wrapper function for perl_parse() - use cmdline style, parameter list
int cmePerlParserCmdLineInit (int argc, char **argv, PerlInterpreter *myPerl);
// Wrapper function for perl_parse() - use a single instruction string as parameter
int cmePerlParserInstruction (char *perlInstruction, PerlInterpreter *myPerl);
// Wrapper function for perl_parse() - use a single script filename as parameter
int cmePerlParserRun (PerlInterpreter *myPerl);
// Wrapper function cmePerlParserCmdLineInit() and call_pv()
int cmePerlParserScriptFunction (const char *fName, PerlInterpreter *myPerl, char **args,
                                 int numArgs, char **results, int maxResults, int *returnedResults);
#endif // PERL_INTERPRETER_H_INCLUDED
