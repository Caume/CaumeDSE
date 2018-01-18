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
#include "common.h"

int cmePerlParserCmdLineInit (int argc, char **argv, PerlInterpreter *myPerl)
{
    int result;

/*  //This procedure was implemented to fix issues with PERL 5.8.8 but it causes some problems on later versions.
    //It is now being removed since we are requiring PERL >= 5.10.0 anyway and it is more efficient to have a single
    //PERL instance.
    perl_destruct(myPerl);
    perl_free(myPerl);
    myPerl=perl_alloc();
    perl_construct(myPerl);
*/
    if ((!argv[0])||(!argv[1])) //Error, critical parameter missing!
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePerlParserCmdLineInit(), error, argv[0] or [1] missing!\n");
#endif
        return(1);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmePerlParserCmdLineInit(), perl_parse() will be executed"
            " with: argc=%d, argv[0]=%s, argv[1]=%s and environment=NULL.\n",argc,argv[0],argv[1]);
#endif
    PL_perl_destruct_level = 0; //Destruct and reconstruct again the Perl interpreter to avoid namespace problems.
    PL_origalen=1; // don't let $0 assignment update the proctitle or embedding[0] - from perldoc.perl.org/perlembed.html
    result=perl_parse(myPerl, xs_init, argc, argv, NULL);
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    if (result) // Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePerlParserCmdLineInit(), perl_parse() : %d"
                " !\n",result);
#endif
        return(2);
    }
    return(0);
}

int cmePerlParserInstruction (char *perlInstruction, PerlInterpreter *myPerl)
{
    int result;
    char *ilist[3];
    const char prg[]="CaumeDSE";
    const char eParam[]="-e";

    PL_perl_destruct_level = 0; //Destruct and reconstruct again the Perl interpreter to avoid namespace problems.

/*  //This procedure was implemented to fix issues with PERL 5.8.8 but it causes some problems on later versions.
    //It is now being removed since we are requiring PERL >= 5.10.0 anyway and it is more efficient to have a single
    //PERL instance.
    perl_destruct(myPerl);
    perl_free(myPerl);
    myPerl=perl_alloc();
    perl_construct(myPerl);
*/
    ilist[0]=(char *)prg;
    ilist[1]=(char *)eParam;
    ilist[2]=perlInstruction;
    result=perl_parse(myPerl, NULL, 3, ilist, NULL);
    if (result) // Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePerlParserInstruction(), perl_parse() : %d"
                " !\n",result);
#endif
        return(1);
    }
    return(0);
}

int cmePerlParserRun (PerlInterpreter *myPerl)
{
    int result=0;
    result=perl_run(myPerl);
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmePerlParserRun(), perl_run() executed"
            " with code %d.\n",result);
#endif
    return(0);
}

int cmePerlParserScriptFunction (const char *fName, PerlInterpreter *myPerl, char **args,
                                 int numArgs, char **results, int maxResults, int *returnedResults)
{
    int cont=0;
    char *string=NULL;

    cmePerlParserRun (myPerl); // No cmePerlParserCmdLineInit(), in order to allow
                               // a single initialization with several calls to functions!!!!
                               // i.e. global variables in perl script are persistent :-)
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    for (cont=0; cont <numArgs; cont++)         //push parameters to the stack
    {
        XPUSHs(sv_2mortal(newSVpv(args[cont],0)));
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmePerlParserScriptFunction(), Pushed %d parameters"
            " to perl function %s.\n",numArgs,fName);
#endif
    PUTBACK;
    *returnedResults = call_pv(fName, G_ARRAY|G_KEEPERR|G_EVAL);
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmePerlParserScriptFunction(), Got %d results"
            " from perl function %s.\n",*returnedResults,fName);
#endif
    if (*returnedResults > maxResults)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePerlParserScriptFunction(), more results than expected (%d); not enough memory!\n",
                   *returnedResults);
#endif
        return(1);
    }
    SPAGAIN;
    for (cont=0; cont < *returnedResults; cont++)           //pop results from the stack
    {
        string=SvPVx_nolen(POPs);
        results[cont]=NULL; //initialization needed by cmeStrConstrAppend. Note: caller is responsible for freeing **results array!
        cmeStrConstrAppend(&(results[cont]),"%s",string);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmePerlParserScriptFunction(), Prepared %d results"
            " from perl function %s.\n",*returnedResults,fName);
#endif
    PUTBACK;
    FREETMPS;
    LEAVE;
    return(0);
}
