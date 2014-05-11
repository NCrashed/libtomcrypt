/* LTC_PKCS Header Info */
module tomcrypt.pkcs;

import core.stdc.config : c_ulong;

import tomcrypt.prng;

extern(C) nothrow:

/* ===> LTC_PKCS #1 -- RSA Cryptography <=== */
version(LTC_PKCS_1)
{
    
    enum ltc_pkcs_1_v1_5_blocks
    {
        LTC_LTC_PKCS_1_EMSA   = 1,        /* Block type 1 (LTC_PKCS #1 v1.5 signature padding) */
        LTC_LTC_PKCS_1_EME    = 2         /* Block type 2 (LTC_PKCS #1 v1.5 encryption padding) */
    }
    enum  LTC_LTC_PKCS_1_EMSA = ltc_pkcs_1_v1_5_blocks.LTC_LTC_PKCS_1_EMSA;
    enum  LTC_LTC_PKCS_1_EME  = ltc_pkcs_1_v1_5_blocks.LTC_LTC_PKCS_1_EME;
    
    enum ltc_pkcs_1_paddings
    {
        LTC_LTC_PKCS_1_V1_5   = 1,        /* LTC_PKCS #1 v1.5 padding (\sa ltc_pkcs_1_v1_5_blocks) */
        LTC_LTC_PKCS_1_OAEP   = 2,        /* LTC_PKCS #1 v2.0 encryption padding */
        LTC_LTC_PKCS_1_PSS    = 3         /* LTC_PKCS #1 v2.1 signature padding */
    }
    enum  LTC_LTC_PKCS_1_V1_5 = ltc_pkcs_1_paddings.LTC_LTC_PKCS_1_V1_5;
    enum  LTC_LTC_PKCS_1_OAEP = ltc_pkcs_1_paddings.LTC_LTC_PKCS_1_OAEP;
    enum  LTC_LTC_PKCS_1_PSS  = ltc_pkcs_1_paddings.LTC_LTC_PKCS_1_PSS;
        
    int pkcs_1_mgf1(      int            hash_idx,
                    const ubyte*         seed, c_ulong seedlen,
                          ubyte*         mask, c_ulong masklen);
    
    int pkcs_1_i2osp(void *n, c_ulong modulus_len, ubyte*  _out);
    int pkcs_1_os2ip(void *n, ubyte*  _in, c_ulong inlen);
    
    /* *** v1.5 padding */
    int pkcs_1_v1_5_encode(const ubyte*         msg, 
                                 c_ulong        msglen,
                                 int            block_type,
                                 c_ulong        modulus_bitlen,
                                 prng_state*    prng, 
                                 int            prng_idx,
                                 ubyte*         _out, 
                                 c_ulong*       outlen);
    
    int pkcs_1_v1_5_decode(const ubyte*         msg, 
                                 c_ulong        msglen,
                                 int            block_type,
                                 c_ulong        modulus_bitlen,
                                 ubyte*         _out, 
                                 c_ulong*       outlen,
                                 int*           is_valid);
    
    /* *** v2.1 padding */
    int pkcs_1_oaep_encode(const ubyte*    msg,            c_ulong      msglen,
                           const ubyte*    lparam,         c_ulong      lparamlen,
                                 c_ulong   modulus_bitlen, prng_state*  prng,
                                 int       prng_idx,       int          hash_idx,
                                 ubyte*     _out,          c_ulong*     outlen);
    
    int pkcs_1_oaep_decode(const ubyte*    msg,            c_ulong  msglen,
                           const ubyte*    lparam,         c_ulong  lparamlen,
                                 c_ulong   modulus_bitlen, int      hash_idx,
                                 ubyte*    _out,           c_ulong* outlen,
                                 int*      res);
    
    int pkcs_1_pss_encode(const ubyte*     msghash,        c_ulong       msghashlen,
                                c_ulong    saltlen,        prng_state*   prng,     
                                int        prng_idx,       int           hash_idx,
                                c_ulong    modulus_bitlen,
                                ubyte*     _out,           c_ulong*      outlen);
    
    int pkcs_1_pss_decode(const ubyte*     msghash,        c_ulong    msghashlen,
                          const ubyte*     sig,            c_ulong    siglen,
                                c_ulong    saltlen,        int        hash_idx,
                                c_ulong    modulus_bitlen, int*       res);

} /* LTC_PKCS_1 */

/* ===> LTC_PKCS #5 -- Password Based Cryptography <=== */
version(LTC_PKCS_5)
{
    
    /* Algorithm #1 (old) */
    int pkcs_5_alg1(const ubyte*  password, c_ulong password_len, 
                    const ubyte*  salt, 
                    int iteration_count,  int hash_idx,
                    ubyte* _out, c_ulong* outlen);
    
    /* Algorithm #2 (new) */
    int pkcs_5_alg2(const ubyte* password, c_ulong password_len, 
                    const ubyte* salt,     c_ulong salt_len,
                    int iteration_count,   int hash_idx,
                    ubyte*       _out,     c_ulong* outlen);

} /* LTC_PKCS_5 */

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_pkcs.h,v $ */
/* $Revision: 1.8 $ */
/* $Date: 2007/05/12 14:32:35 $ */