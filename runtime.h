/***
Copyright 2010-2026 by Omar Alejandro Herrera Reyna

    Caume Data Security Engine, also known as CaumeDSE is released under the
    GNU General Public License by the Copyright holder, with the additional
    exemption that compiling, linking, and/or using OpenSSL is allowed.

***/
#ifndef RUNTIME_H_INCLUDED
#define RUNTIME_H_INCLUDED

int cmeSetupRuntime(unsigned char **bIn,unsigned char **bOut,PerlInterpreter **myPerl);
int cmeEndRuntime(unsigned char **bIn,unsigned char **bOut,PerlInterpreter **myPerl);

#endif // RUNTIME_H_INCLUDED
