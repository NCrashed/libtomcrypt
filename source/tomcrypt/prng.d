/* ---- PRNG Stuff ---- */
module tomcrypt.prng;

import core.stdc.config;
import tomcrypt.custom;
import tomcrypt.tomcrypt;

extern(C) nothrow:

version(LTC_YARROW)
{
    struct yarrow_prng 
    {
        int                   cipher, hash;
        ubyte[MAXBLOCKSIZE]   pool;
        symmetric_CTR         ctr;
        mixin(LTC_MUTEX_TYPE("prng_lock"));
    }
}

version(LTC_RC4)
{
    struct rc4_prng 
    {
        int x, y;
        ubyte[256] buf;
    }
}

version(LTC_FORTUNA)
{
    struct fortuna_prng 
    {
        hash_state[LTC_FORTUNA_POOLS] pool;     /* the  pools */
    
        symmetric_key skey;
    
        ubyte[32]       K;          /* the current key */
        ubyte[16]       IV;         /* IV for CTR mode */
        
        c_ulong         pool_idx,   /* current pool we will add to */
                        pool0_len,  /* length of 0'th pool */
                        wd;            
    
        ulong           reset_cnt;  /* number of times we have reset */
        mixin(LTC_MUTEX_TYPE("prng_lock"));
    }
}

version(LTC_SOBER128)
{
    struct sober128_prng {
        uint[17]     R,          /* Working storage for the shift register */
                     initR;      /* saved register contents */ 
        uint         konst,      /* key dependent constant */
                     sbuf;       /* partial word encryption buffer */
    
        int          nbuf,       /* number of part-word stream bits buffered */
                     flag,       /* first add_entropy call or not? */
                     set;        /* did we call add_entropy to set key? */
        
    }
}

union prng_state 
{
    char[1] dummy;
    version(LTC_YARROW)
    {
        yarrow_prng    yarrow;
    }
    version(LTC_RC4)
    {
        rc4_prng       rc4;
    }
    version(LTC_FORTUNA)
    {
        fortuna_prng   fortuna;
    }
    version(LTC_SOBER128)
    {
        sober128_prng  sober128;
    }
}

/** PRNG descriptor */
struct ltc_prng_descriptor 
{
    /** Name of the PRNG */
    char *name;
    /** size _in bytes of exported state */
    int  export_size;
    /** Start a PRNG state
        @param prng   [_out] The state to initialize
        @return CRYPT_OK if successful
    */
    int function(prng_state *prng) nothrow start;
    /** Add entropy to the PRNG
        @param _in         The entropy
        @param inlen      Length of the entropy (octets)\
        @param prng       The PRNG state
        @return CRYPT_OK if successful
    */
    int function(const ubyte* _in, c_ulong inlen, prng_state *prng) nothrow add_entropy;
    /** Ready a PRNG state to read from
        @param prng       The PRNG state to ready
        @return CRYPT_OK if successful
    */
    int function(prng_state *prng) nothrow ready;
    /** Read from the PRNG
        @param _out     [_out] Where to store the data
        @param outlen  Length of data desired (octets)
        @param prng    The PRNG state to read from
        @return Number of octets read
    */
    c_ulong function(ubyte* _out, c_ulong outlen, prng_state *prng) nothrow read;
    /** Terminate a PRNG state
        @param prng   The PRNG state to terminate
        @return CRYPT_OK if successful
    */
    int function(prng_state *prng) nothrow done;
    /** Export a PRNG state  
        @param _out     [_out] The destination for the state
        @param outlen  [_in/_out] The max size and resulting size of the PRNG state
        @param prng    The PRNG to export
        @return CRYPT_OK if successful
    */
    int function(ubyte* _out, c_ulong *outlen, prng_state *prng) nothrow pexport;
    /** Import a PRNG state
        @param _in      The data to import
        @param inlen   The length of the data to import (octets)
        @param prng    The PRNG to initialize/import
        @return CRYPT_OK if successful
    */
    int function(const ubyte* _in, c_ulong inlen, prng_state *prng) nothrow pimport;
    /** Self-test the PRNG
        @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
    */
    int function() nothrow test;
}

extern __gshared ltc_prng_descriptor[] prng_descriptor;

version(LTC_YARROW)
{
    int yarrow_start(prng_state *prng);
    int yarrow_add_entropy(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int yarrow_ready(prng_state *prng);
    c_ulong yarrow_read(ubyte* _out, c_ulong outlen, prng_state *prng);
    int yarrow_done(prng_state *prng);
    int  yarrow_export(ubyte* _out, c_ulong *outlen, prng_state *prng);
    int  yarrow_import(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int  yarrow_test();
    extern const __gshared ltc_prng_descriptor yarrow_desc;
}

version(LTC_FORTUNA)
{
    int fortuna_start(prng_state *prng);
    int fortuna_add_entropy(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int fortuna_ready(prng_state *prng);
    c_ulong fortuna_read(ubyte* _out, c_ulong outlen, prng_state *prng);
    int fortuna_done(prng_state *prng);
    int  fortuna_export(ubyte* _out, c_ulong *outlen, prng_state *prng);
    int  fortuna_import(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int  fortuna_test();
    extern const __gshared ltc_prng_descriptor fortuna_desc;
}

version(LTC_RC4)
{
    int rc4_start(prng_state *prng);
    int rc4_add_entropy(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int rc4_ready(prng_state *prng);
    c_ulong rc4_read(ubyte* _out, c_ulong outlen, prng_state *prng);
    int  rc4_done(prng_state *prng);
    int  rc4_export(ubyte* _out, c_ulong *outlen, prng_state *prng);
    int  rc4_import(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int  rc4_test();
    extern const __gshared ltc_prng_descriptor rc4_desc;
}

version(LTC_SPRNG)
{
    int sprng_start(prng_state *prng);
    int sprng_add_entropy(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int sprng_ready(prng_state *prng);
    c_ulong sprng_read(ubyte* _out, c_ulong outlen, prng_state *prng);
    int sprng_done(prng_state *prng);
    int  sprng_export(ubyte* _out, c_ulong *outlen, prng_state *prng);
    int  sprng_import(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int  sprng_test();
    extern const __gshared ltc_prng_descriptor sprng_desc;
}

version(LTC_SOBER128)
{
    int sober128_start(prng_state *prng);
    int sober128_add_entropy(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int sober128_ready(prng_state *prng);
    c_ulong sober128_read(ubyte* _out, c_ulong outlen, prng_state *prng);
    int sober128_done(prng_state *prng);
    int  sober128_export(ubyte* _out, c_ulong *outlen, prng_state *prng);
    int  sober128_import(const ubyte* _in, c_ulong inlen, prng_state *prng);
    int  sober128_test();
    extern const __gshared ltc_prng_descriptor sober128_desc;
}

int find_prng(const char *name);
int register_prng(const ltc_prng_descriptor *prng);
int unregister_prng(const ltc_prng_descriptor *prng);
int prng_is_valid(int idx);
mixin(LTC_MUTEX_PROTO("ltc_prng_mutex"));

/* Slow RNG you **might** be able to use to seed a PRNG with.  Be careful as this
 * might not work on all platforms as planned
 */
c_ulong rng_get_bytes(ubyte* _out, 
                      c_ulong outlen, 
                      void function() callback);

int rng_make_prng(int bits, int wprng, prng_state *prng, void function() callback);


/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_prng.h,v $ */
/* $Revision: 1.9 $ */
/* $Date: 2007/05/12 14:32:35 $ */