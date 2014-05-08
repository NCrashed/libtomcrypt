module tomcrypt.custom;

import core.stdc.stdlib;
import core.stdc.string;
import core.sys.posix.time;

/* macros for various libc functions you can change for embedded targets */
//#ifndef XMALLOC
//   #ifdef malloc 
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XMALLOC  malloc
//#endif
alias XMALLOC = malloc;

//#ifndef XREALLOC
//   #ifdef realloc 
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XREALLOC realloc
//#endif
alias XREALLOC = realloc;

//#ifndef XCALLOC
//   #ifdef calloc 
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XCALLOC  calloc
//#endif
alias XCALLOC = calloc;

//#ifndef XFREE
//   #ifdef free
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XFREE    free
//#endif
alias XFREE = free;

//#ifndef XMEMSET
//   #ifdef memset
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XMEMSET  memset
//#endif
alias XMEMSET = memset;

//#ifndef XMEMCPY
//   #ifdef memcpy
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XMEMCPY  memcpy
//#endif
alias XMEMCPY = memcpy;

//#ifndef XMEMCMP
//   #ifdef memcmp 
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XMEMCMP  memcmp
//#endif
alias XMEMCMP = memcmp;

//#ifndef XSTRCMP
//   #ifdef strcmp
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XSTRCMP strcmp
//#endif
alias XSTRCMP = strcmp;

//#ifndef XCLOCK
//#define XCLOCK   clock
//#endif
alias XCLOCK = clock;

//#ifndef XCLOCKS_PER_SEC
//#define XCLOCKS_PER_SEC CLOCKS_PER_SEC
//#endif
alias XCLOCKS_PER_SEC = CLOCKS_PER_SEC;

//#ifndef XQSORT
//   #ifdef qsort
//   #define LTC_NO_PROTOTYPES
//   #endif
//#define XQSORT qsort
//#endif
alias XQSORT = qsort;

/* Easy button? */
version(LTC_EASY)
{
   version = LTC_NO_CIPHERS;
   version = LTC_RIJNDAEL;
   version = LTC_BLOWFISH;
   version = LTC_DES;
   version = LTC_CAST5;
   
   version = LTC_NO_MODES;
   version = LTC_ECB_MODE;
   version = LTC_CBC_MODE;
   version = LTC_CTR_MODE;
   
   version = LTC_NO_HASHES;
   version = LTC_SHA1;
   version = LTC_SHA512;
   version = LTC_SHA384;
   version = LTC_SHA256;
   version = LTC_SHA224;
   
   version = LTC_NO_MACS;
   version = LTC_HMAC;
   version = LTC_OMAC;
   version = LTC_CCM_MODE;

   version = LTC_NO_PRNGS;
   version = LTC_SPRNG;
   version = LTC_YARROW;
   version = LTC_DEVRANDOM;
   version = TRY_URANDOM_FIRST;
      
   version = LTC_NO_PK;
   version = LTC_MRSA;
   version = LTC_MECC;
}

/* Use small code where possible */
/* version = LTC_SMALL_CODE; */

/* Enable self-test test vector checking */
version(LTC_NO_TEST) {}
else
{
    version = LTC_TEST;
}

/* clean the stack of functions which put private information on stack */
/* version = LTC_CLEAN_STACK; */

/* disable all file related functions */
/* version = LTC_NO_FILE; */

/* disable all forms of ASM */
/* version = LTC_NO_ASM; */

/* disable FAST mode */
/* version = LTC_NO_FAST; */

/* disable BSWAP on x86 */
/* version = LTC_NO_BSWAP; */

/* ---> Symmetric Block Ciphers <--- */
version(LTC_NO_CIPHERS) {}
else
{
    version = LTC_BLOWFISH;
    version = LTC_RC2;
    version = LTC_RC5;
    version = LTC_RC6;
    version = LTC_SAFERP;
    version = LTC_RIJNDAEL;
    version = LTC_XTEA;
    
    /* _TABLES tells it to use tables during setup, _SMALL means to use the smaller scheduled key format
     * (saves 4KB of ram), _ALL_TABLES enables all tables during setup */
    version = LTC_TWOFISH;
    
    version(LTC_NO_TABLES)
    {
        version = LTC_TWOFISH_SMALL;
    }
    else
    {
        version = LTC_TWOFISH_TABLES;
        /* version = LTC_TWOFISH_ALL_TABLES; */
    }

    /* version = LTC_TWOFISH_SMALL; */
    /* LTC_DES includes EDE triple-LTC_DES */
    version = LTC_DES;
    version = LTC_CAST5;
    version = LTC_NOEKEON;
    version = LTC_SKIPJACK;
    version = LTC_SAFER;
    version = LTC_KHAZAD;
    version = LTC_ANUBIS;
    version = LTC_ANUBIS_TWEAK;
    version = LTC_KSEED;
    version = LTC_KASUMI;
}

/* ---> Block Cipher Modes of Operation <--- */
version(LTC_NO_MODES) {}
else
{
    version = LTC_CFB_MODE;
    version = LTC_OFB_MODE;
    version = LTC_ECB_MODE;
    version = LTC_CBC_MODE;
    version = LTC_CTR_MODE;
    
    /* F8 chaining mode */
    version = LTC_F8_MODE;
    
    /* LRW mode */
    version = LTC_LRW_MODE;
    version(LTC_NO_TABLES) {}
    else
    {
        /* like GCM mode this will enable 16 8x128 tables [64KB] that make
        * seeking very fast.  
        */
       version = LRW_TABLES;
    }

    /* XTS mode */
    version = LTC_XTS_MODE;
}

/* ---> One-Way Hash Functions <--- */
version(LTC_NO_HASHES) {}
else
{ 
    version = LTC_CHC_HASH;
    version = LTC_WHIRLPOOL;
    version = LTC_SHA512;
    version = LTC_SHA384;
    version = LTC_SHA256;
    version = LTC_SHA224;
    version = LTC_TIGER;
    version = LTC_SHA1;
    version = LTC_MD5;
    version = LTC_MD4;
    version = LTC_MD2;
    version = LTC_RIPEMD128;
    version = LTC_RIPEMD160;
    version = LTC_RIPEMD256;
    version = LTC_RIPEMD320;
}

/* ---> MAC functions <--- */
version(LTC_NO_MACS) {}
else
{
    version = LTC_HMAC;
    version = LTC_OMAC;
    version = LTC_PMAC;
    version = LTC_XCBC;
    version = LTC_F9_MODE;
    version = LTC_PELICAN;
    
    version(LTC_PELICAN)
    {
        version(LTC_RIJNDAEL) {}
        else
        {
            pragma(error, "Pelican-MAC requires LTC_RIJNDAEL");
        }
    }
    
    /* ---> Encrypt + Authenticate Modes <--- */
    
    version = LTC_EAX_MODE;
    version(LTC_EAX_MODE)
    {
        version(LTC_CTR_MODE) {}
        else
        {
            pragma(error, "LTC_EAX_MODE requires CTR and LTC_OMAC mode");
        }
        
        version(LTC_OMAC) {}
        else
        {
            pragma(error, "LTC_EAX_MODE requires CTR and LTC_OMAC mode");
        }
    }
    
    version = LTC_OCB_MODE;
    version = LTC_CCM_MODE;
    version = LTC_GCM_MODE;
    
    /* Use 64KiB tables */
    version(LTC_NO_TABLES) {}
    else
    {
        version = LTC_GCM_TABLES;
    }
    
    /* USE SSE2? requires GCC works on x86_32 and x86_64*/
    version(LTC_GCM_TABLES)
    {
        /* version = LTC_GCM_TABLES_SSE2; */
    }
}

/* Various tidbits of modern neatoness */
version = LTC_BASE64;

/* --> Pseudo Random Number Generators <--- */
version (LTC_NO_PRNGS) {}
else
{
    /* Yarrow */
    version = LTC_YARROW;
    /* which descriptor of AES to use?  */
    /* 0 = rijndael_enc 1 = aes_enc, 2 = rijndael [full], 3 = aes [full] */
    enum LTC_YARROW_AES = 0;
    
    version(LTC_YARROW)
    {
        version(LTC_CTR_MODE) {}
        else
        {
            pragma(error, "LTC_YARROW requires LTC_CTR_MODE chaining mode to be defined!");
        }
    }
    
    /* a PRNG that simply reads from an available system source */
    version = LTC_SPRNG;
    
    /* The LTC_RC4 stream cipher */
    version = LTC_RC4;
    
    /* Fortuna PRNG */
    version = LTC_FORTUNA;
    /* reseed every N calls to the read function */
    enum LTC_FORTUNA_WD    = 10;
    /* number of pools (4..32) can save a bit of ram by lowering the count */
    enum LTC_FORTUNA_POOLS = 32;
    
    /* Greg's LTC_SOBER128 PRNG ;-0 */
    version = LTC_SOBER128;
    
    /* the *nix style /dev/random device */
    version = LTC_DEVRANDOM;
    /* try /dev/urandom before trying /dev/random */
    version = TRY_URANDOM_FIRST;
}

/* ---> math provider? <--- */
version(LTC_NO_MATH) {}
else
{
    /* LibTomMath */
    /* version = LTM_LTC_DESC; */
    
    /* TomsFastMath */
    /* version = TFM_LTC_DESC; */
}

/* ---> Public Key Crypto <--- */
version(LTC_NO_PK) {}
else
{
    /* Include RSA support */
    version = LTC_MRSA;
    
    /* Include Katja (a Rabin variant like RSA) */
    /* version = MKAT; */ 
    
    /* Digital Signature Algorithm */
    version = LTC_MDSA;
    
    /* ECC */
    version = LTC_MECC;
    
    /* use Shamir's trick for point mul (speeds up signature verification) */
    version = LTC_ECC_SHAMIR;
    
    version(TFM_LTC_DESC)
    {
        version(LTC_MECC)
        {
            version = LTC_MECC_ACCEL;
        }
    }
    
    /* do we want fixed point ECC */
    /* version = LTC_MECC_FP; */
    
    /* Timing Resistant? */
    /* version = LTC_ECC_TIMING_RESISTANT; */
}

/* LTC_PKCS #1 (RSA) and #5 (Password Handling) stuff */
version(LTC_NO_PKCS) {}
else
{
    version = LTC_PKCS_1;
    version = LTC_PKCS_5;
    
    /* Include ASN.1 DER (required by DSA/RSA) */
    version = LTC_DER;
}

/* cleanup */

version(LTC_MECC)
{
    /* Supported ECC Key Sizes */
    version(LTC_NO_CURVES) {}
    else
    {
       version = ECC112;
       version = ECC128;
       version = ECC160;
       version = ECC192;
       version = ECC224;
       version = ECC256;
       version = ECC384;
       version = ECC521;
    }
}

/* Include the MPI functionality?  (required by the PK algorithms) */
version(LTC_MECC) version = MPI;
version(LTC_MRSA) version = MPI;
version(LTC_MDSA) version = MPI;
version(MKATJA) version = MPI;

version(LTC_MRSA)
{
   version = LTC_PKCS_1;
}

version(LTC_DER)
{
    version(MPI) {}
    else
    {
        pragma(error, "ASN.1 DER requires MPI functionality");
    }
}

version(LTC_MDSA) {version(LTC_DER) {} else pragma(error, "PK requires ASN.1 DER functionality, make sure LTC_DER is enabled");}
version(LTC_MRSA) {version(LTC_DER) {} else pragma(error, "PK requires ASN.1 DER functionality, make sure LTC_DER is enabled");}
version(LTC_MECC) {version(LTC_DER) {} else pragma(error, "PK requires ASN.1 DER functionality, make sure LTC_DER is enabled");}
version(MKATJA)   {version(LTC_DER) {} else pragma(error, "PK requires ASN.1 DER functionality, make sure LTC_DER is enabled");}

/* THREAD management */
version(LTC_PTHREAD)
{
    import core.sys.posix.pthread;
    
    string LTC_MUTEX_GLOBAL(string x) {return "pthread_mutex_t "~x~" = PTHREAD_MUTEX_INITIALIZER;";}
    string LTC_MUTEX_PROTO(string x)  {return "extern pthread_mutex_t "~x~";";}
    string LTC_MUTEX_TYPE(string x)   {return "pthread_mutex_t "~x~";";}
    void  LTC_MUTEX_INIT(pthread_mutex_t x) { pthread_mutex_init(x, null); }
    alias LTC_MUTEX_LOCK = pthread_mutex_lock;
    alias LTC_MUTEX_UNLOCK = pthread_mutex_unlock;
}
else
{
    void tcl_nothing(T...)(T args) {}
    
    /* default no functions */
    string LTC_MUTEX_GLOBAL(string x) {return "";}
    string LTC_MUTEX_PROTO(string x) {return "";}
    string LTC_MUTEX_TYPE(string x) {return "";}
    alias LTC_MUTEX_INIT = tcl_nothing;
    alias LTC_MUTEX_LOCK = tcl_nothing;
    alias LTC_MUTEX_UNLOCK = tcl_nothing;
}

/* Debuggers */

/* define this if you use Valgrind, note: it CHANGES the way SOBER-128 and LTC_RC4 work (see the code) */
/* version = LTC_VALGRIND; */

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_custom.h,v $ */
/* $Revision: 1.73 $ */
/* $Date: 2007/05/12 14:37:41 $ */