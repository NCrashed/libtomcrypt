/* ---- HASH FUNCTIONS ---- */
module tomcrypt.hash;

import core.stdc.config;
import core.stdc.stdio;

import tomcrypt.custom;

extern(C) nothrow:

version(LTC_SHA512)
{
    struct sha512_state 
    {
        ulong  length;
        ulong[8] state;
        c_ulong curlen;
        ubyte[128] buf;
    };
}

version(LTC_SHA256)
{
    struct sha256_state 
    {
        ulong length;
        uint[8] state;
        uint curlen;
        ubyte[64] buf;
    }
}

version(LTC_SHA1)
{
    struct sha1_state 
    {
        ulong length;
        uint[5] state;
        uint curlen;
        ubyte[64] buf;
    }
}

version(LTC_MD5)
{
    struct md5_state 
    {
        ulong length;
        uint[4] state;
        uint curlen;
        ubyte[64] buf;
    }
}

version(LTC_MD4)
{
    struct md4_state 
    {
        ulong length;
        uint[4] state;
        uint curlen;
        ubyte[64] buf;
    }
}

version(LTC_TIGER)
{
    struct tiger_state 
    {
        ulong[3] state;
        ulong length;
        c_ulong curlen;
        ubyte[64] buf;
    }
}

version(LTC_MD2)
{
    struct md2_state 
    {
        ubyte[16] chksum;
        ubyte[48] X;
        ubyte[16] buf;
        c_ulong curlen;
    }
}

version(LTC_RIPEMD128)
{
    struct rmd128_state 
    {
        ulong length;
        ubyte[64] buf;
        uint curlen;
        uint[4] state;
    }
}

version(LTC_RIPEMD160)
{
    struct rmd160_state 
    {
        ulong length;
        ubyte[64] buf;
        uint curlen;
        uint[5] state;
    }
}

version(LTC_RIPEMD256)
{
    struct rmd256_state {
        ulong length;
        ubyte[64] buf;
        uint curlen;
        uint[8] state;
    }
}

version(LTC_RIPEMD320)
{
    struct rmd320_state 
    {
        ulong length;
        ubyte[64] buf;
        uint curlen;
        uint[10] state;
    }
}

version(LTC_WHIRLPOOL)
{
    struct whirlpool_state 
    {
        ulong length;
        ulong[8] state;
        ubyte[64] buf;
        uint curlen;
    }
}

version(LTC_CHC_HASH)
{
    struct chc_state 
    {
        ulong length;
        ubyte[MAXBLOCKSIZE] state, buf;
        uint curlen;
    }
}

union hash_state 
{
    char dummy[1];
    version(LTC_CHC_HASH)
    {
        chc_state chc;
    }
    
    version(LTC_WHIRLPOOL)
    {
        whirlpool_state whirlpool;
    }
    
    version(LTC_SHA512)
    {
        sha512_state sha512;
    }
    
    version(LTC_SHA256)
    {
        sha256_state sha256;
    }
    
    version(LTC_SHA1)
    {
        sha1_state   sha1;
    }
    
    version(LTC_MD5)
    {
        md5_state    md5;
    }
    
    version(LTC_MD4)
    {
        md4_state    md4;
    }
    
    version(LTC_MD2)
    {
        md2_state    md2;
    }
    
    version(LTC_TIGER)
    {
        tiger_state  tiger;
    }
    
    version(LTC_RIPEMD128)
    {
        rmd128_state rmd128;
    }
    
    version(LTC_RIPEMD160)
    {
        rmd160_state rmd160;
    }
    
    version(LTC_RIPEMD256)
    {
        rmd256_state rmd256;
    }
    
    version(LTC_RIPEMD320)
    {
        rmd320_state rmd320;
    }
    
    void *data;
}

/** hash descriptor */
struct ltc_hash_descriptor 
{
    /** name of hash */
    char *name;
    /** internal ID */
    ubyte ID;
    /** Size of digest in octets */
    c_ulong hashsize;
    /** Input block size in octets */
    c_ulong blocksize;
    /** ASN.1 OID */
    c_ulong OID[16];
    /** Length of DER encoding */
    c_ulong OIDlen;

    /** Init a hash state
      @param hash   The hash to initialize
      @return CRYPT_OK if successful
    */
    int function(hash_state *hash) init;
    /** Process a block of data 
      @param hash   The hash state
      @param in     The data to hash
      @param inlen  The length of the data (octets)
      @return CRYPT_OK if successful
    */
    int function(hash_state *hash, const ubyte *_in, c_ulong inlen) process;
    /** Produce the digest and store it
      @param hash   The hash state
      @param out    [out] The destination of the digest
      @return CRYPT_OK if successful
    */
    int function(hash_state *hash, ubyte *_out) done;
    /** Self-test
      @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
    */
    int function() test;

    /* accelerated hmac callback: if you need to-do multiple packets just use the generic hmac_memory and provide a hash callback */
    int  function(     const ubyte *key, c_ulong  keylen,
                       const ubyte *_in,  c_ulong  inlen, 
                             ubyte *_out, c_ulong *outlen) hmac_block;

} 
extern __gshared ltc_hash_descriptor[] hash_descriptor;

version(LTC_CHC_HASH)
{
    int chc_register(int cipher);
    int chc_init(hash_state * md);
    int chc_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int chc_done(hash_state * md, ubyte *hash);
    int chc_test(void);
    extern __gshared const ltc_hash_descriptor chc_desc;
}

version(LTC_WHIRLPOOL)
{
    int whirlpool_init(hash_state * md);
    int whirlpool_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int whirlpool_done(hash_state * md, ubyte *hash);
    int whirlpool_test(void);
    extern __gshared const ltc_hash_descriptor whirlpool_desc;
}

version(LTC_SHA512)
{
    int sha512_init(hash_state * md);
    int sha512_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int sha512_done(hash_state * md, ubyte *hash);
    int sha512_test(void);
    extern __gshared const ltc_hash_descriptor sha512_desc;
}

version(LTC_SHA384)
{
    version(LTC_SHA512) {}
    else
    {
        pragma(error, "LTC_SHA512 is required for LTC_SHA384");
    }
    
    int sha384_init(hash_state * md);
    alias sha384_process = sha512_process;
    int sha384_done(hash_state * md, ubyte *hash);
    int sha384_test(void);
    extern __gshared const ltc_hash_descriptor sha384_desc;
}

version(LTC_SHA256)
{
    int sha256_init(hash_state * md);
    int sha256_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int sha256_done(hash_state * md, ubyte *hash);
    int sha256_test(void);
    extern __gshared const ltc_hash_descriptor sha256_desc;

    version(LTC_SHA224)
    {
        version(LTC_SHA256) {}
        else
        {
            pragma(error, "LTC_SHA256 is required for LTC_SHA224");
        }
    
        int sha224_init(hash_state * md);
        alias sha224_process = sha256_process;
        int sha224_done(hash_state * md, ubyte *hash);
        int sha224_test(void);
        extern __gshared const ltc_hash_descriptor sha224_desc;
    }
}

version(LTC_SHA1)
{
    int sha1_init(hash_state * md);
    int sha1_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int sha1_done(hash_state * md, ubyte *hash);
    int sha1_test(void);
    extern __gshared const ltc_hash_descriptor sha1_desc;
}

version(LTC_MD5)
{
    int md5_init(hash_state * md);
    int md5_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int md5_done(hash_state * md, ubyte *hash);
    int md5_test(void);
    extern __gshared const ltc_hash_descriptor md5_desc;
}

version(LTC_MD4)
{
    int md4_init(hash_state * md);
    int md4_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int md4_done(hash_state * md, ubyte *hash);
    int md4_test(void);
    extern __gshared const ltc_hash_descriptor md4_desc;
}

version(LTC_MD2)
{
    int md2_init(hash_state * md);
    int md2_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int md2_done(hash_state * md, ubyte *hash);
    int md2_test(void);
    extern __gshared const ltc_hash_descriptor md2_desc;
}

version(LTC_TIGER)
{
    int tiger_init(hash_state * md);
    int tiger_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int tiger_done(hash_state * md, ubyte *hash);
    int tiger_test(void);
    extern __gshared const ltc_hash_descriptor tiger_desc;
}

version(LTC_RIPEMD128)
{
    int rmd128_init(hash_state * md);
    int rmd128_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int rmd128_done(hash_state * md, ubyte *hash);
    int rmd128_test(void);
    extern __gshared const ltc_hash_descriptor rmd128_desc;
}

version(LTC_RIPEMD160)
{
    int rmd160_init(hash_state * md);
    int rmd160_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int rmd160_done(hash_state * md, ubyte *hash);
    int rmd160_test(void);
    extern __gshared const ltc_hash_descriptor rmd160_desc;
}

version(LTC_RIPEMD256)
{
    int rmd256_init(hash_state * md);
    int rmd256_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int rmd256_done(hash_state * md, ubyte *hash);
    int rmd256_test(void);
    extern __gshared const ltc_hash_descriptor rmd256_desc;
}

version(LTC_RIPEMD320)
{
    int rmd320_init(hash_state * md);
    int rmd320_process(hash_state * md, const ubyte *_in, c_ulong inlen);
    int rmd320_done(hash_state * md, ubyte *hash);
    int rmd320_test(void);
    extern __gshared const ltc_hash_descriptor rmd320_desc;
}


int find_hash(const char *name);
int find_hash_id(ubyte ID);
int find_hash_oid(const c_ulong *ID, c_ulong IDlen);
int find_hash_any(const char *name, int digestlen);
int register_hash(const ltc_hash_descriptor *hash);
int unregister_hash(const ltc_hash_descriptor *hash);
int hash_is_valid(int idx);

mixin(LTC_MUTEX_PROTO("ltc_hash_mutex"));

int hash_memory(int hash, 
                const ubyte *_in,  c_ulong inlen, 
                      ubyte *_out, c_ulong *outlen);
int hash_memory_multi(int hash, ubyte *_out, c_ulong *outlen,
                      const ubyte *_in, c_ulong inlen, ...);
int hash_filehandle(int hash, FILE *_in, ubyte *_out, c_ulong *outlen);
int hash_file(int hash, const char *fname, ubyte *_out, c_ulong *outlen);

/* a simple macro for making hash "process" functions */                 
string HASH_PROCESS(string func_name, string compress_name, string state_var, string block_size)
{
    return q{
int }~func_name~q{ (hash_state * md, const ubyte *_in, c_ulong inlen)               
{                                                                                           
    c_ulong n;                                                                        
    int           err;                                                                      
    mixin(LTC_ARGCHK("md != NULL"));                                                                 
    mixin(LTC_ARGCHK("_in != NULL"));                                                                 
    if (md.}~state_var~q{.curlen > sizeof(md.}~state_var~q{.buf)) {                             
       return CRYPT_INVALID_ARG;                                                            
    }                                                                                       
    while (inlen > 0) {                                                                     
        if (md.}~state_var~q{.curlen == 0 && inlen >= }~block_size~q{) {                           
           if ((err = }~compress_name~q{ (md, cast(ubyte *)_in)) != CRYPT_OK) {               
              return err;                                                                   
           }                                                                                
           md.}~state_var~q{.length += }~block_size~q{ * 8;                                        
           _in            += }~block_size~q{;                                                    
           inlen          -= }~block_size~q{;                                                    
        } else {
            
           auto MIN(T,U)(T a, T b) { return a > b ? b : a;}                                                                             
           n = MIN(inlen, (}~block_size~q{ - md-> }~state_var~q{ .curlen)); 
                                         
           memcpy(md.}~state_var~q{.buf + md.}~state_var~q{.curlen, _in, cast(size_t)n);              
           md.}~state_var~q{.curlen += n;                                                     
           _in            += n;                                                             
           inlen          -= n;                                                             
           if (md.}~state_var~q{.curlen == }~block_size~q{) {                                      
              if ((err = }~compress_name~q{ (md, md.}~state_var~q{.buf)) != CRYPT_OK) {            
                 return err;                                                                
              }                                                                             
              md.}~state_var~q{.length += 8*}~block_size~q{;                                       
              md.}~state_var~q{.curlen = 0;                                                   
           }                                                                                
       }                                                                                    
    }                                                                                       
    return CRYPT_OK;                                                                        
}
    };
}
/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_hash.h,v $ */
/* $Revision: 1.22 $ */
/* $Date: 2007/05/12 14:32:35 $ */
