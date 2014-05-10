module tomcrypt.mac;

import core.stdc.config;

version(LTC_HMAC)
{
    struct hmac_state 
    {
         hash_state     md;
         int            hash;
         hash_state     hashstate;
         ubyte*         key;
    }

    int hmac_init(hmac_state *hmac, int hash, const ubyte* key, c_ulong keylen);
    int hmac_process(hmac_state *hmac, const ubyte* _in, c_ulong inlen);
    int hmac_done(hmac_state *hmac, ubyte* _out, c_ulong *outlen);
    int hmac_test();
    int hmac_memory(int hash, 
                    const ubyte* key, c_ulong keylen,
                    const ubyte* _in,  c_ulong inlen, 
                          ubyte* _out, c_ulong *outlen);
    int hmac_memory_multi(int hash, 
                    const ubyte* key,  c_ulong keylen,
                          ubyte* _out,  c_ulong *outlen,
                    const ubyte* _in,   c_ulong inlen, ...);
    int hmac_file(int hash, const char *fname, const ubyte* key,
                  c_ulong keylen, 
                  ubyte* dst, c_ulong *dstlen);
}

version(LTC_OMAC)
{

    struct omac_state
    {
        int                     cipher_idx, 
                                buflen,
                                blklen;
        ubyte[MAXBLOCKSIZE]     block,
                                prev;
        ubyte[2][MAXBLOCKSIZE]  Lu;
        symmetric_key           key;
    }
    
    int omac_init(omac_state *omac, int cipher, const ubyte* key, c_ulong keylen);
    int omac_process(omac_state *omac, const ubyte* _in, c_ulong inlen);
    int omac_done(omac_state *omac, ubyte* _out, c_ulong *outlen);
    int omac_memory(int cipher, 
                   const ubyte* key, c_ulong keylen,
                   const ubyte* _in,  c_ulong inlen,
                         ubyte* _out, c_ulong *outlen);
    int omac_memory_multi(int cipher, 
                    const ubyte* key, c_ulong keylen,
                          ubyte* _out, c_ulong *outlen,
                    const ubyte* _in,  c_ulong inlen, ...);
    int omac_file(int cipher, 
                  const ubyte* key, c_ulong keylen,
                  const          char *filename, 
                        ubyte* _out, c_ulong *outlen);
    int omac_test();
} /* LTC_OMAC */

version(LTC_PMAC)
{

    struct pmac_state
    {
       ubyte[32][MAXBLOCKSIZE]     Ls;            /* L shifted by i bits to the left */
       ubyte[MAXBLOCKSIZE]         Li,            /* value of Li [current value, we calc from previous recall] */
                                   Lr,            /* L * x^-1 */
                                   block,         /* currently accumulated block */
                                   checksum;      /* current checksum */
    
       symmetric_key     key;                     /* scheduled key for cipher */
       c_ulong           block_index;             /* index # for current block */
       int               cipher_idx,              /* cipher idx */
                         block_len,               /* length of block */
                         buflen;                  /* number of bytes in the buffer */
    }
    
    int pmac_init(pmac_state *pmac, int cipher, const ubyte* key, c_ulong keylen);
    int pmac_process(pmac_state *pmac, const ubyte* _in, c_ulong inlen);
    int pmac_done(pmac_state *pmac, ubyte* _out, c_ulong *outlen);
    
    int pmac_memory(int cipher, 
                   const ubyte* key, c_ulong keylen,
                   const ubyte* msg, c_ulong msglen,
                         ubyte* _out, c_ulong *outlen);
    
    int pmac_memory_multi(int cipher, 
                    const ubyte* key, c_ulong keylen,
                          ubyte* _out, c_ulong *outlen,
                    const ubyte* _in, c_ulong inlen, ...);
    
    int pmac_file(int cipher, 
                 const ubyte* key, c_ulong keylen,
                 const          char *filename, 
                       ubyte* _out, c_ulong *outlen);
    
    int pmac_test();
    
    /* internal functions */
    int pmac_ntz(c_ulong x);
    void pmac_shift_xor(pmac_state *pmac);

} /* PMAC */

version(LTC_EAX_MODE)
{
    version(LTC_OMAC) {}
    else
    {
        pragma(error, "LTC_EAX_MODE requires LTC_OMAC and CTR");
    }
    
    version(LTC_CTR_MODE) {}
    else
    {
        pragma(error, "LTC_EAX_MODE requires LTC_OMAC and CTR");
    }


    struct eax_state
    {
       ubyte[MAXBLOCKSIZE] N;
       symmetric_CTR ctr;
       omac_state    headeromac, ctomac;
    }
    
    int eax_init(eax_state *eax, int cipher, const ubyte* key, c_ulong keylen,
                 const ubyte* nonce, c_ulong noncelen,
                 const ubyte* header, c_ulong headerlen);
    
    int eax_encrypt(eax_state *eax, const ubyte* pt, ubyte* ct, c_ulong length);
    int eax_decrypt(eax_state *eax, const ubyte* ct, ubyte* pt, c_ulong length);
    int eax_addheader(eax_state *eax, const ubyte* header, c_ulong length);
    int eax_done(eax_state *eax, ubyte* tag, c_ulong *taglen);
    
    int eax_encrypt_authenticate_memory(int cipher,
        const ubyte* key,    c_ulong keylen,
        const ubyte* nonce,  c_ulong noncelen,
        const ubyte* header, c_ulong headerlen,
        const ubyte* pt,     c_ulong ptlen,
              ubyte* ct,
              ubyte* tag,    c_ulong *taglen);
    
    int eax_decrypt_verify_memory(int cipher,
        const ubyte* key,    c_ulong keylen,
        const ubyte* nonce,  c_ulong noncelen,
        const ubyte* header, c_ulong headerlen,
        const ubyte* ct,     c_ulong ctlen,
              ubyte* pt,
              ubyte* tag,    c_ulong taglen,
              int           *stat);
    
    int eax_test();
} /* EAX MODE */

version(LTC_OCB_MODE)
{
    struct ocb_state
    {
        ubyte[MAXBLOCKSIZE]      L;         /* L value */
        ubyte[32][MAXBLOCKSIZE]  Ls;        /* L shifted by i bits to the left */
        ubyte[MAXBLOCKSIZE]      Li,        /* value of Li [current value, we calc from previous recall] */
                                 Lr,        /* L * x^-1 */
                                 R,         /* R value */
                                 checksum;  /* current checksum */
    
        symmetric_key       key;                     /* scheduled key for cipher */
        c_ulong             block_index;             /* index # for current block */
        int                 cipher,                  /* cipher idx */
                            block_len;               /* length of block */
    }
    
    int ocb_init(ocb_state *ocb, int cipher, 
                 const ubyte* key, c_ulong keylen, const ubyte* nonce);
    
    int ocb_encrypt(ocb_state *ocb, const ubyte* pt, ubyte* ct);
    int ocb_decrypt(ocb_state *ocb, const ubyte* ct, ubyte* pt);
    
    int ocb_done_encrypt(ocb_state *ocb, 
                         const ubyte* pt,  c_ulong ptlen,
                               ubyte* ct, 
                               ubyte* tag, c_ulong *taglen);
    
    int ocb_done_decrypt(ocb_state *ocb, 
                         const ubyte* ct,  c_ulong ctlen,
                               ubyte* pt, 
                         const ubyte* tag, c_ulong taglen, int *stat);
    
    int ocb_encrypt_authenticate_memory(int cipher,
        const ubyte* key,    c_ulong keylen,
        const ubyte* nonce,  
        const ubyte* pt,     c_ulong ptlen,
              ubyte* ct,
              ubyte* tag,    c_ulong *taglen);
    
    int ocb_decrypt_verify_memory(int cipher,
        const ubyte* key,    c_ulong keylen,
        const ubyte* nonce,  
        const ubyte* ct,     c_ulong ctlen,
              ubyte* pt,
        const ubyte* tag,    c_ulong taglen,
              int           *stat);
    
    int ocb_test();
    
    /* internal functions */
    void ocb_shift_xor(ocb_state *ocb, ubyte* Z);
    int ocb_ntz(c_ulong x);
    int s_ocb_done(ocb_state *ocb, const ubyte* pt, c_ulong ptlen,
                   ubyte* ct, ubyte* tag, c_ulong *taglen, int mode);

} /* LTC_OCB_MODE */

version(LTC_CCM_MODE)
{

    enum CCM_ENCRYPT = 0;
    enum CCM_DECRYPT = 1;
    
    int ccm_memory(int cipher,
        const ubyte* key,    c_ulong keylen,
        symmetric_key       *uskey,
        const ubyte* nonce,  c_ulong noncelen,
        const ubyte* header, c_ulong headerlen,
              ubyte* pt,     c_ulong ptlen,
              ubyte* ct,
              ubyte* tag,    c_ulong *taglen,
                        int  direction);
    
    int ccm_test();

} /* LTC_CCM_MODE */

version(LRW_MODE)
{
    void gcm_gf_mult(const ubyte* a, const ubyte* b, ubyte* c);
}
else version(LTC_GCM_MODE)
{
    void gcm_gf_mult(const ubyte* a, const ubyte* b, ubyte* c);
}


/* table shared between GCM and LRW */
//#if defined(LTC_GCM_TABLES) || defined(LRW_TABLES) || ((defined(LTC_GCM_MODE) || defined(LTC_GCM_MODE)) && defined(LTC_FAST))
version(LTC_GCM_TABLES)
{
    extern __gshared const(ubyte[]) gcm_shift_table;
}
else version(LRW_TABLES)
{
    extern __gshared const(ubyte[]) gcm_shift_table;
}
else
{
    version(LTC_FAST)
    {
        version(LTC_GCM_MODE)
        {
            extern __gshared const(ubyte[]) gcm_shift_table;
        }
        else version(LTC_GCM_MODE)
        {
            extern __gshared const(ubyte[]) gcm_shift_table;
        }
    }
}

version(LTC_GCM_MODE)
{
    enum GCM_ENCRYPT = 0;
    enum GCM_DECRYPT = 1;
    
    enum LTC_GCM_MODE_IV    = 0;
    enum LTC_GCM_MODE_AAD   = 1;
    enum LTC_GCM_MODE_TEXT  = 2;
    
    struct gcm_state
    { 
       symmetric_key       K;
       ubyte[16]           H,        /* multiplier */
                           X,        /* accumulator */
                           Y,        /* counter */
                           Y_0,      /* initial counter */
                           buf;      /* buffer for stuff */
    
       int                 cipher,       /* which cipher */
                           ivmode,       /* Which mode is the IV in? */
                           mode,         /* mode the GCM code is in */
                           buflen;       /* length of data in buf */
    
       ulong64             totlen,       /* 64-bit counter used for IV and AAD */
                           pttotlen;     /* 64-bit counter for the PT */
    
        version(LTC_GCM_TABLES)
        {
            
            version(LTC_GCM_TABLES_SSE2)
            {
                align(16) ubyte[16][256][16]       PC;  /* 16 tables of 8x128 */
            }
            else
            {
                ubyte[16][256][16]       PC;  /* 16 tables of 8x128 */
            }
        }  
    }
    
    void gcm_mult_h(gcm_state *gcm, ubyte* I);
    
    int gcm_init(gcm_state *gcm, int cipher,
                 const ubyte* key, int keylen);
    
    int gcm_reset(gcm_state *gcm);
    
    int gcm_add_iv(gcm_state *gcm, 
                   const ubyte* IV,     c_ulong IVlen);
    
    int gcm_add_aad(gcm_state *gcm,
                   const ubyte* adata,  c_ulong adatalen);
    
    int gcm_process(gcm_state *gcm,
                         ubyte* pt,     c_ulong ptlen,
                         ubyte* ct,
                         int direction);
    
    int gcm_done(gcm_state *gcm, 
                         ubyte* tag,    c_ulong *taglen);
    
    int gcm_memory(      int           cipher,
                   const ubyte* key,    c_ulong keylen,
                   const ubyte* IV,     c_ulong IVlen,
                   const ubyte* adata,  c_ulong adatalen,
                         ubyte* pt,     c_ulong ptlen,
                         ubyte* ct, 
                         ubyte* tag,    c_ulong *taglen,
                                   int direction);
    int gcm_test();

} /* LTC_GCM_MODE */

version(LTC_PELICAN)
{

    struct pelican_state
    {
        symmetric_key K;
        ubyte[16]     state;
        int           buflen;
    }
    
    int pelican_init(pelican_state *pelmac, const ubyte* key, c_ulong keylen);
    int pelican_process(pelican_state *pelmac, const ubyte* _in, c_ulong inlen);
    int pelican_done(pelican_state *pelmac, ubyte* _out);
    int pelican_test();
    
    int pelican_memory(const ubyte* key, c_ulong keylen,
                       const ubyte* _in, c_ulong inlen,
                             ubyte* _out);

}

version(LTC_XCBC)
{
    /* add this to "keylen" to xcbc_init to use a pure three-key XCBC MAC */
    enum LTC_XCBC_PURE  = 0x8000UL;
    
    struct xcbc_state
    {
       ubyte[3][MAXBLOCKSIZE] K;
       ubyte[MAXBLOCKSIZE]    IV;
    
       symmetric_key key;
    
                 int cipher,
                     buflen,
                     blocksize;
    }
    
    int xcbc_init(xcbc_state *xcbc, int cipher, const ubyte* key, c_ulong keylen);
    int xcbc_process(xcbc_state *xcbc, const ubyte* _in, c_ulong inlen);
    int xcbc_done(xcbc_state *xcbc, ubyte* _out, c_ulong *outlen);
    int xcbc_memory(int cipher, 
                   const ubyte* key, c_ulong keylen,
                   const ubyte* _in,  c_ulong inlen,
                         ubyte* _out, c_ulong *outlen);
    int xcbc_memory_multi(int cipher, 
                    const ubyte* key, c_ulong keylen,
                          ubyte* _out, c_ulong *outlen,
                    const ubyte* _in,  c_ulong inlen, ...);
    int xcbc_file(int cipher, 
                  const ubyte* key, c_ulong keylen,
                  const          char *filename, 
                        ubyte* _out, c_ulong *outlen);
    int xcbc_test();
}

version(LTC_F9_MODE)
{

    struct f9_state
    {
       ubyte[MAXBLOCKSIZE] akey,
                           ACC,
                           IV;
    
       symmetric_key key;
    
                 int cipher,
                     buflen,
                     keylen,
                     blocksize;
    }
    
    int f9_init(f9_state *f9, int cipher, const ubyte* key, c_ulong keylen);
    int f9_process(f9_state *f9, const ubyte* _in, c_ulong inlen);
    int f9_done(f9_state *f9, ubyte* _out, c_ulong *outlen);
    int f9_memory(int cipher, 
                   const ubyte* key, c_ulong keylen,
                   const ubyte* _in,  c_ulong inlen,
                         ubyte* _out, c_ulong *outlen);
    int f9_memory_multi(int cipher, 
                    const ubyte* key, c_ulong keylen,
                          ubyte* _out, c_ulong *outlen,
                    const ubyte* _in,  c_ulong inlen, ...);
    int f9_file(int cipher, 
                  const ubyte* key, c_ulong keylen,
                  const          char *filename, 
                        ubyte* _out, c_ulong *outlen);
    int f9_test();

}


/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_mac.h,v $ */
/* $Revision: 1.23 $ */
/* $Date: 2007/05/12 14:37:41 $ */