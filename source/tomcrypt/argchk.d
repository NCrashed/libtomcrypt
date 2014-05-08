module tomcrypt.argchk;

import tomcrypt.cfg;
import std.string;

extern(C) nothrow:

/* Defines the LTC_ARGCHK macro used within the library */
/* ARGTYPE is defined in mycrypt_cfg.h */
static if(ARGTYPE == 0)
{
    import core.stdc.signal;
    
    /* this is the default LibTomCrypt macro  */
    void crypt_argchk(char* v, char* s, int d);
    
    string LTC_ARGCHK(string x)
    {
        return "if (!"~x~") { crypt_argchk("~x~", __FILE__, __LINE__);";
    }
    alias LTC_ARGCHKVD = LTC_ARGCHK;    
} 
else static if(ARGTYPE == 1)
{
    /* fatal type of error */
    string LTC_ARGCHK(string x)
    {
        return "assert("~x~");";
    }
    alias LTC_ARGCHKVD = LTC_ARGCHK;
} 
else static if(ARGTYPE == 2)
{
    string LTC_ARGCHK(string x)
    {
        return "if (!"~x~") { fprintf(stderr, \"\nwarning: ARGCHK failed at %s:%d\n\", file.toStringz, line);";
    }
    alias LTC_ARGCHKVD = LTC_ARGCHK;    
} 
else static if(ARGTYPE == 3)
{
    string LTC_ARGCHK(string x)
    {
        return "";
    }
    alias LTC_ARGCHKVD = LTC_ARGCHK;    
} 
else static if(ARGTYPE == 4)
{
    string LTC_ARGCHK(string x)
    {
        return "if (!("~x~")) return CRYPT_INVALID_ARG;";
    }
    string LTC_ARGCHKVD(string x)
    {
        return "if (!("~x~")) return;";
    }
}


/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_argchk.h,v $ */
/* $Revision: 1.5 $ */
/* $Date: 2006/08/27 20:50:21 $ */