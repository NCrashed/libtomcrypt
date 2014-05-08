/**
* This is the build config file.
*
* With this you can setup what to inlcude/exclude automatically during any build.  Just comment
* out the line that enum's the word for the thing you want to remove.  phew!
*/
module tomcrypt.cfg;

import core.stdc.config;

extern(C) nothrow:

/* type of argument checking, 0=default, 1=fatal and 2=error+continue, 3=nothing */
enum ARGTYPE  = 0;


/* Controls endianess and size of registers.  Leave uncommented to get platform neutral [slower] code 
 * 
 * Note: in order to use the optimized macros your platform must support unaligned 32 and 64 bit read/writes.
 * The x86 platforms allow this but some others [ARM for instance] do not.  On those platforms you **MUST**
 * use the portable [slower] macros.
 */

/* No asm is a quick way to disable anything "not portable" */
version(LTC_NO_ASM)
{
    version = LTC_NO_ROLC;
    version = LTC_NO_BSWAP;  
}
else
{
    version(LittleEndian)
    {
        version = ENDIAN_LITTLE;
    }
    version(BitEndian)
    {
        version = ENDIAN_BIG;
    }
    
    /* detect x86-32 machines somewhat */
    version(x86)
    {
        version = ENDIAN_32BITWORD;
        version(LTC_NO_FAST) {}
        else
        {
            version = LTC_FAST;
            alias LTC_FAST_TYPE = c_ulong;
        }
    }
    
    /* detects MIPS R5900 processors (PS2) */
    version(MIPS64)
    {
        version = ENDIAN_64BITWORD;
    }
    version(MIPS32)
    {
        version = ENDIAN_32BITWORD;
    }
    
    /* detect amd64 */
    version(X86_64)
    {
        version = ENDIAN_64BITWORD; 
        version(LTC_NO_FAST) {}
        else
        {
            version = LTC_FAST;
            alias LTC_FAST_TYPE = c_ulong;
        }
    }
    
    /* detect PPC32 */
    version(PPC)
    {
        version = ENDIAN_32BITWORD;
        version(LTC_NO_FAST) {}
        else
        {
            version = LTC_FAST;
            alias LTC_FAST_TYPE = c_ulong;
        }
    }
    
    /* detect sparc and sparc64 */
    version(SPARC)
    {
        version = ENDIAN_32BITWORD;
    }
    version(SPARC64)
    {
        version = ENDIAN_64BITWORD;
    }
}

/* version = ENDIAN_LITTLE; */
/* version = ENDIAN_BIG; */

/* version = ENDIAN_32BITWORD; */
/* version = ENDIAN_64BITWORD; */

version(ENDIAN_BIG)
{
    version(ENDIAN_32BITWORD) {}
    else version(ENDIAN_64BITWORD) {}
    else
    {
        pragma(msg, "You must specify a word size as well as endianess in tomcrypt_cfg.h");
    }
} 
else version(ENDIAN_LITTLE)
{
    version(ENDIAN_32BITWORD) {}
    else version(ENDIAN_64BITWORD) {}
    else
    {
        pragma(msg, "You must specify a word size as well as endianess in tomcrypt_cfg.h");
    }
} else
{
    version = ENDIAN_NEUTRAL;
}

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_cfg.h,v $ */
/* $Revision: 1.19 $ */
/* $Date: 2006/12/04 02:19:48 $ */
