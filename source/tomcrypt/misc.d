/* ---- LTC_BASE64 Routines ---- */
module tomcrypt.misc;

import core.stdc.config;

extern(C) nothrow:

version(LTC_BASE64)
{
    int base64_encode(const ubyte* _in,  c_ulong len, 
                            ubyte* _out, c_ulong *outlen);
    
    int base64_decode(const ubyte* _in,  c_ulong len, 
                            ubyte* _out, c_ulong *outlen);
}

/* ---- MEM routines ---- */
void zeromem(void *dst, size_t len);
void burn_stack(c_ulong len);

const(char*) error_to_string(int err);

extern const __gshared char *crypt_build_settings;

/* ---- HMM ---- */
int crypt_fsa(void *mp, ...);

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_misc.h,v $ */
/* $Revision: 1.5 $ */
/* $Date: 2007/05/12 14:32:35 $ */
