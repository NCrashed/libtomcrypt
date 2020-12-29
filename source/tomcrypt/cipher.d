/** ---- SYMMETRIC KEY STUFF -----
*
* We put each of the ciphers scheduled keys in their own structs then we put all of 
* the key formats in one union.  This makes the function prototypes easier to use.
*/
module tomcrypt.cipher;

import tomcrypt.custom;
import tomcrypt.tomcrypt;
import core.stdc.config;

extern(C) nothrow:

version(LTC_BLOWFISH)
{
    struct blowfish_key 
    {
       uint[4][256] S;
       uint[18] K;
    }
}

version(LTC_RC5)
{
    struct rc5_key 
    {
       int rounds;
       uint[50] K;
    }
}

version(LTC_RC6)
{
    struct rc6_key 
    {
       uint[44] K;
    }
}

version(LTC_SAFERP)
{
    struct saferp_key 
    {
       ubyte[33][16] K;
       long rounds;
    }
}

version(LTC_RIJNDAEL)
{
    struct rijndael_key 
    {
       uint[60] eK, dK;
       int Nr;
    }
}

version(LTC_KSEED)
{
    struct kseed_key 
    {
        uint[32] K, dK;
    }
}

version(LTC_KASUMI)
{
    struct kasumi_key 
    {
        uint[8] KLi1, KLi2,
                KOi1, KOi2, KOi3,
                KIi1, KIi2, KIi3;
    }
}

version(LTC_XTEA)
{
    struct xtea_key 
    {
       c_ulong[32] A, B;
    }
}

version(LTC_TWOFISH)
{
    version(LTC_TWOFISH_SMALL)
    {
       struct twofish_key 
       {
          uint[40]  K;
          ubyte[32] S;
          ubyte     start;
       }
    }
    else
    {
       struct twofish_key 
       {
          uint[4][256] S;
          uint[40] K;
       }
    }
}

version(LTC_SAFER)
{
    enum LTC_SAFER_K64_DEFAULT_NOF_ROUNDS     = 6;
    enum LTC_SAFER_K128_DEFAULT_NOF_ROUNDS    = 10;
    enum LTC_SAFER_SK64_DEFAULT_NOF_ROUNDS    = 8;
    enum LTC_SAFER_SK128_DEFAULT_NOF_ROUNDS   = 10;
    enum LTC_SAFER_MAX_NOF_ROUNDS             = 13;
    enum LTC_SAFER_BLOCK_LEN                  = 8;
    enum LTC_SAFER_KEY_LEN    = (1 + LTC_SAFER_BLOCK_LEN * (1 + 2 * LTC_SAFER_MAX_NOF_ROUNDS));
    alias ubyte[LTC_SAFER_BLOCK_LEN] safer_block_t;
    alias ubyte[LTC_SAFER_KEY_LEN] safer_key_t;
    struct safer_key { safer_key_t key; };
}

version(LTC_RC2)
{
    struct rc2_key { uint[64] xkey; };
}

version(LTC_DES)
{
    struct des_key 
    {
        uint[32] ek, dk;
    }
    
    struct des3_key 
    {
        uint[3][32] ek, dk;
    }
}

version(LTC_CAST5)
{
    struct cast5_key 
    {
        uint[32] K;
        uint keylen;
    }
}
    
version(LTC_NOEKEON)
{
    struct noekeon_key 
    {
        uint[4] K, dK;
    }
}

version(LTC_SKIPJACK)
{ 
    struct skipjack_key 
    {
        ubyte[10] key;
    }
}

version(LTC_KHAZAD)
{
    struct khazad_key 
    {
       ulong[8 + 1] roundKeyEnc; 
       ulong[8 + 1] roundKeyDec; 
    }
}

version(LTC_ANUBIS)
{
    struct anubis_key 
    { 
       int keyBits; 
       int R; 
       uint[18 + 1][4] roundKeyEnc; 
       uint[18 + 1][4] roundKeyDec; 
    } 
}

version(LTC_MULTI2)
{
    struct multi2_key 
    {
        int N;
        uint[8] uk;
    }
}

union Symmetric_key
{
    version(LTC_DES)
    {
        des_key des;
        des3_key des3;
    }
    
    version(LTC_RC2)
    {
        rc2_key rc2;
    }
    
    version(LTC_SAFER)
    {
        safer_key safer;
    }
    
    version(LTC_TWOFISH)
    {
        twofish_key  twofish;
    }
    
    version(LTC_BLOWFISH)
    {
       blowfish_key blowfish;
    }
    
    version(LTC_RC5)
    {
        rc5_key      rc5;
    }
    
    version(LTC_RC6)
    {
        rc6_key      rc6;
    }
    
    version(LTC_SAFERP)
    {
       saferp_key   saferp;
    }
    
    version(LTC_RIJNDAEL)
    {
        rijndael_key rijndael;
    }
    
    version(LTC_XTEA)
    {
        xtea_key     xtea;
    }
    
    version(LTC_CAST5)
    {
        cast5_key    cast5;
    }
    
    version(LTC_NOEKEON)
    { 
        noekeon_key  noekeon;
    }   
    
    version(LTC_SKIPJACK)
    {
        skipjack_key skipjack;
    }
    
    version(LTC_KHAZAD)
    {
        khazad_key   khazad;
    }
    
    version(LTC_ANUBIS)
    {
        anubis_key   anubis;
    }
    
    version(LTC_KSEED)
    {
        kseed_key    kseed;
    }
    
    version(LTC_KASUMI)
    {
        kasumi_key   kasumi;
    }  
    
    version(LTC_MULTI2)
    {
        multi2_key   multi2;
    }
    
    void   *data;
}
alias symmetric_key = Symmetric_key;

version(LTC_ECB_MODE)
{
    /** A block cipher ECB structure */
    struct symmetric_ECB
    {
       /** The index of the cipher chosen */
       int                 cipher, 
       /** The block size of the given cipher */
                           blocklen;
       /** The scheduled key */                       
       symmetric_key       key;
    } 
}

version(LTC_CFB_MODE)
{
    /** A block cipher CFB structure */
    struct  symmetric_CFB
    {
       /** The index of the cipher chosen */
       int                 cipher, 
       /** The block size of the given cipher */                        
                           blocklen, 
       /** The padding offset */
                           padlen;
       /** The current IV */
       ubyte[MAXBLOCKSIZE] IV,
       /** The pad used to encrypt/decrypt */ 
                           pad;
       /** The scheduled key */
       symmetric_key       key;
    }
}

version(LTC_OFB_MODE)
{
    /** A block cipher OFB structure */
    struct symmetric_OFB 
    {
       /** The index of the cipher chosen */
       int                 cipher, 
       /** The block size of the given cipher */                        
                           blocklen, 
       /** The padding offset */
                           padlen;
       /** The current IV */
       ubyte[MAXBLOCKSIZE] IV;
       /** The scheduled key */
       symmetric_key       key;
    }
}

version(LTC_CBC_MODE)
{
    /** A block cipher CBC structure */
    struct symmetric_CBC
    {
       /** The index of the cipher chosen */
       int                 cipher, 
       /** The block size of the given cipher */                        
                           blocklen;
       /** The current IV */
       ubyte[MAXBLOCKSIZE] IV;
       /** The scheduled key */
       symmetric_key       key;
    }
}


version(LTC_CTR_MODE)
{
    /** A block cipher CTR structure */
    struct symmetric_CTR 
    {
       /** The index of the cipher chosen */
       int                 cipher,
       /** The block size of the given cipher */                        
                           blocklen, 
       /** The padding offset */
                           padlen, 
       /** The mode (endianess) of the CTR, 0==little, 1==big */
                           mode,
       /** counter width */
                           ctrlen;
    
       /** The counter */                       
       ubyte[MAXBLOCKSIZE] ctr, 
       /** The pad used to encrypt/decrypt */                       
                           pad;
       /** The scheduled key */
       symmetric_key       key;
    }
}


version(LTC_LRW_MODE)
{
    /** A LRW structure */
    struct symmetric_LRW
    {
        /** The index of the cipher chosen (must be a 128-bit block cipher) */
        int               cipher;
    
        /** The current IV */
        ubyte[16]     IV,
     
        /** the tweak key */
                      tweak,
    
        /** The current pad, it's the product of the first 15 bytes against the tweak key */
                      pad;
    
        /** The scheduled symmetric key */
        symmetric_key     key;
    
        version(LRW_TABLES)
        {
            /** The pre-computed multiplication table */
            ubyte[16][256][16] PC;
        }
    } 
}

version(LTC_F8_MODE)
{
    /** A block cipher F8 structure */
    struct symmetric_F8
    {
       /** The index of the cipher chosen */
       int                 cipher, 
       /** The block size of the given cipher */                        
                           blocklen, 
       /** The padding offset */
                           padlen;
       /** The current IV */
       ubyte[MAXBLOCKSIZE] IV,
                           MIV;
       /** Current block count */
       uint             blockcnt;
       /** The scheduled key */
       symmetric_key       key;
    }
}


/** cipher descriptor table, last entry has "name == NULL" to mark the end of table */
struct ltc_cipher_descriptor 
{
   /** name of cipher */
   char *name;
   /** internal ID */
   ubyte ID;
   /** min keysize (octets) */
   int  min_key_length, 
   /** max keysize (octets) */
        max_key_length, 
   /** block size (octets) */
        block_length, 
   /** default number of rounds */
        default_rounds;
   /** Setup the cipher 
      @param key         The input symmetric key
      @param keylen      The length of the input key (octets)
      @param num_rounds  The requested number of rounds (0==default)
      @param skey        [out] The destination of the scheduled key
      @return CRYPT_OK if successful
   */
   int  function(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey) nothrow setup;
   /** Encrypt a block
      @param pt      The plaintext
      @param ct      [out] The ciphertext
      @param skey    The scheduled key
      @return CRYPT_OK if successful
   */
   int function(const ubyte *pt, ubyte *ct, symmetric_key *skey) nothrow ecb_encrypt;
   /** Decrypt a block
      @param ct      The ciphertext
      @param pt      [out] The plaintext
      @param skey    The scheduled key
      @return CRYPT_OK if successful
   */
   int function(const ubyte *ct, ubyte *pt, symmetric_key *skey) nothrow ecb_decrypt;
   /** Test the block cipher
       @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
   */
   int function() nothrow test;

   /** Terminate the context 
      @param skey    The scheduled key
   */
   void function(symmetric_key *skey) nothrow done;      

   /** Determine a key size
       @param keysize    [in/out] The size of the key desired and the suggested size
       @return CRYPT_OK if successful
   */
   int  function(int *keysize) nothrow keysize;

/** Accelerators **/
   /** Accelerated ECB encryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int function(const ubyte *pt, ubyte *ct, c_ulong blocks, symmetric_key *skey) nothrow accel_ecb_encrypt;

   /** Accelerated ECB decryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int function(const ubyte *ct, ubyte *pt, c_ulong blocks, symmetric_key *skey) nothrow accel_ecb_decrypt;

   /** Accelerated CBC encryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int function(const ubyte *pt, ubyte *ct, c_ulong blocks, ubyte *IV, symmetric_key *skey) nothrow accel_cbc_encrypt;

   /** Accelerated CBC decryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int function(const ubyte *ct, ubyte *pt, c_ulong blocks, ubyte *IV, symmetric_key *skey) nothrow accel_cbc_decrypt;

   /** Accelerated CTR encryption 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param mode    little or big endian counter (mode=0 or mode=1)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int function(const ubyte *pt, ubyte *ct, c_ulong blocks, ubyte *IV, int mode, symmetric_key *skey) nothrow accel_ctr_encrypt;

   /** Accelerated LRW 
       @param pt      Plaintext
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param tweak   The LRW tweak
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int function(const ubyte *pt, ubyte *ct, c_ulong blocks, ubyte *IV, const ubyte *tweak, symmetric_key *skey) nothrow accel_lrw_encrypt;

   /** Accelerated LRW 
       @param ct      Ciphertext
       @param pt      Plaintext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param tweak   The LRW tweak
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   int function(const ubyte *ct, ubyte *pt, c_ulong blocks, ubyte *IV, const ubyte *tweak, symmetric_key *skey) nothrow accel_lrw_decrypt;

   /** Accelerated CCM packet (one-shot)
       @param key        The secret key to use
       @param keylen     The length of the secret key (octets)
       @param uskey      A previously scheduled key [optional can be NULL]
       @param nonce      The session nonce [use once]
       @param noncelen   The length of the nonce
       @param header     The header for the session
       @param headerlen  The length of the header (octets)
       @param pt         [out] The plaintext
       @param ptlen      The length of the plaintext (octets)
       @param ct         [out] The ciphertext
       @param tag        [out] The destination tag
       @param taglen     [in/out] The max size and resulting size of the authentication tag
       @param direction  Encrypt or Decrypt direction (0 or 1)
       @return CRYPT_OK if successful
   */
   int function(
       const ubyte *key,    c_ulong keylen,
       symmetric_key       *uskey,
       const ubyte *nonce,  c_ulong noncelen,
       const ubyte *header, c_ulong headerlen,
             ubyte *pt,     c_ulong ptlen,
             ubyte *ct,
             ubyte *tag,    c_ulong *taglen,
                       int  direction) nothrow accel_ccm_memory;

   /** Accelerated GCM packet (one shot)
       @param key        The secret key
       @param keylen     The length of the secret key
       @param IV         The initial vector 
       @param IVlen      The length of the initial vector
       @param adata      The additional authentication data (header)
       @param adatalen   The length of the adata
       @param pt         The plaintext
       @param ptlen      The length of the plaintext (ciphertext length is the same)
       @param ct         The ciphertext
       @param tag        [out] The MAC tag
       @param taglen     [in/out] The MAC tag length
       @param direction  Encrypt or Decrypt mode (GCM_ENCRYPT or GCM_DECRYPT)
       @return CRYPT_OK on success
   */
   int function(
       const ubyte *key,    c_ulong keylen,
       const ubyte *IV,     c_ulong IVlen,
       const ubyte *adata,  c_ulong adatalen,
             ubyte *pt,     c_ulong ptlen,
             ubyte *ct, 
             ubyte *tag,    c_ulong *taglen,
                       int direction) nothrow accel_gcm_memory;

   /** Accelerated one shot LTC_OMAC 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
   */
   int function(
       const ubyte *key, c_ulong keylen,
       const ubyte *_in,  c_ulong inlen,
             ubyte *_out, c_ulong *outlen) nothrow omac_memory;

   /** Accelerated one shot XCBC 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
   */
   int function(
       const ubyte *key, c_ulong keylen,
       const ubyte *_in,  c_ulong inlen,
             ubyte *_out, c_ulong *outlen) nothrow xcbc_memory;

   /** Accelerated one shot F9 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
       @remark Requires manual padding
   */
   int function(
       const ubyte *key, c_ulong keylen,
       const ubyte *_in,  c_ulong inlen,
             ubyte *_out, c_ulong *outlen) nothrow f9_memory;
}

extern __gshared ltc_cipher_descriptor[] cipher_descriptor;

version(LTC_BLOWFISH)
{
    int blowfish_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int blowfish_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int blowfish_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int blowfish_test();
    void blowfish_done(symmetric_key *skey);
    int blowfish_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor blowfish_desc;
}

version(LTC_RC5)
{
    int rc5_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int rc5_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int rc5_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int rc5_test();
    void rc5_done(symmetric_key *skey);
    int rc5_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor rc5_desc;
}

version(LTC_RC6)
{
    int rc6_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int rc6_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int rc6_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int rc6_test();
    void rc6_done(symmetric_key *skey);
    int rc6_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor rc6_desc;
}

version(LTC_RC2)
{
    int rc2_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int rc2_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int rc2_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int rc2_test();
    void rc2_done(symmetric_key *skey);
    int rc2_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor rc2_desc;
}

version(LTC_SAFERP)
{
    int saferp_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int saferp_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int saferp_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int saferp_test();
    void saferp_done(symmetric_key *skey);
    int saferp_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor saferp_desc;
}

version(LTC_SAFER)
{
    int safer_k64_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int safer_sk64_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int safer_k128_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int safer_sk128_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int safer_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *key);
    int safer_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *key);
    int safer_k64_test();
    int safer_sk64_test();
    int safer_sk128_test();
    void safer_done(symmetric_key *skey);
    int safer_64_keysize(int *keysize);
    int safer_128_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor safer_k64_desc, safer_k128_desc, safer_sk64_desc, safer_sk128_desc;
}

version(LTC_RIJNDAEL)
{

    /* make aes an alias */
    alias aes_setup           = rijndael_setup;
    alias aes_ecb_encrypt     = rijndael_ecb_encrypt;
    alias aes_ecb_decrypt     = rijndael_ecb_decrypt;
    alias aes_test            = rijndael_test;
    alias aes_done            = rijndael_done;
    alias aes_keysize         = rijndael_keysize;
    
    alias aes_enc_setup           = rijndael_enc_setup;
    alias aes_enc_ecb_encrypt     = rijndael_enc_ecb_encrypt;
    alias aes_enc_keysize         = rijndael_enc_keysize;
    
    int rijndael_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int rijndael_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int rijndael_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int rijndael_test();
    void rijndael_done(symmetric_key *skey);
    int rijndael_keysize(int *keysize);
    int rijndael_enc_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int rijndael_enc_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    void rijndael_enc_done(symmetric_key *skey);
    int rijndael_enc_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor rijndael_desc, aes_desc;
    extern const __gshared ltc_cipher_descriptor rijndael_enc_desc, aes_enc_desc;
}

version(LTC_XTEA)
{
    int xtea_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int xtea_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int xtea_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int xtea_test();
    void xtea_done(symmetric_key *skey);
    int xtea_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor xtea_desc;
}

version(LTC_TWOFISH)
{
    int twofish_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int twofish_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int twofish_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int twofish_test();
    void twofish_done(symmetric_key *skey);
    int twofish_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor twofish_desc;
}

version(LTC_DES)
{
    int des_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int des_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int des_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int des_test();
    void des_done(symmetric_key *skey);
    int des_keysize(int *keysize);
    int des3_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int des3_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int des3_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int des3_test();
    void des3_done(symmetric_key *skey);
    int des3_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor des_desc, des3_desc;
}

version(LTC_CAST5)
{
    int cast5_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int cast5_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int cast5_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int cast5_test();
    void cast5_done(symmetric_key *skey);
    int cast5_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor cast5_desc;
}

version(LTC_NOEKEON)
{
    int noekeon_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int noekeon_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int noekeon_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int noekeon_test();
    void noekeon_done(symmetric_key *skey);
    int noekeon_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor noekeon_desc;
}

version(LTC_SKIPJACK)
{
    int skipjack_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int skipjack_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int skipjack_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int skipjack_test();
    void skipjack_done(symmetric_key *skey);
    int skipjack_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor skipjack_desc;
}

version(LTC_KHAZAD)
{
    int khazad_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int khazad_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int khazad_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int khazad_test();
    void khazad_done(symmetric_key *skey);
    int khazad_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor khazad_desc;
}

version(LTC_ANUBIS)
{
    int anubis_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int anubis_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int anubis_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int anubis_test();
    void anubis_done(symmetric_key *skey);
    int anubis_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor anubis_desc;
}

version(LTC_KSEED)
{
    int kseed_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int kseed_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int kseed_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int kseed_test();
    void kseed_done(symmetric_key *skey);
    int kseed_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor kseed_desc;
}

version(LTC_KASUMI)
{
    int kasumi_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int kasumi_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int kasumi_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int kasumi_test();
    void kasumi_done(symmetric_key *skey);
    int kasumi_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor kasumi_desc;
}


version(LTC_MULTI2)
{
    int multi2_setup(const ubyte *key, int keylen, int num_rounds, symmetric_key *skey);
    int multi2_ecb_encrypt(const ubyte *pt, ubyte *ct, symmetric_key *skey);
    int multi2_ecb_decrypt(const ubyte *ct, ubyte *pt, symmetric_key *skey);
    int multi2_test();
    void multi2_done(symmetric_key *skey);
    int multi2_keysize(int *keysize);
    extern const __gshared ltc_cipher_descriptor multi2_desc;
}

version(LTC_ECB_MODE)
{
    int ecb_start(int cipher, const ubyte *key, 
                  int keylen, int num_rounds, symmetric_ECB *ecb);
    int ecb_encrypt(const ubyte *pt, ubyte *ct, c_ulong len, symmetric_ECB *ecb);
    int ecb_decrypt(const ubyte *ct, ubyte *pt, c_ulong len, symmetric_ECB *ecb);
    int ecb_done(symmetric_ECB *ecb);
}

version(LTC_CFB_MODE)
{
    int cfb_start(int cipher, const ubyte *IV, const ubyte *key, 
                  int keylen, int num_rounds, symmetric_CFB *cfb);
    int cfb_encrypt(const ubyte *pt, ubyte *ct, c_ulong len, symmetric_CFB *cfb);
    int cfb_decrypt(const ubyte *ct, ubyte *pt, c_ulong len, symmetric_CFB *cfb);
    int cfb_getiv(ubyte *IV, c_ulong *len, symmetric_CFB *cfb);
    int cfb_setiv(const ubyte *IV, c_ulong len, symmetric_CFB *cfb);
    int cfb_done(symmetric_CFB *cfb);
}

version(LTC_OFB_MODE)
{
    int ofb_start(int cipher, const ubyte *IV, const ubyte *key, 
                  int keylen, int num_rounds, symmetric_OFB *ofb);
    int ofb_encrypt(const ubyte *pt, ubyte *ct, c_ulong len, symmetric_OFB *ofb);
    int ofb_decrypt(const ubyte *ct, ubyte *pt, c_ulong len, symmetric_OFB *ofb);
    int ofb_getiv(ubyte *IV, c_ulong *len, symmetric_OFB *ofb);
    int ofb_setiv(const ubyte *IV, c_ulong len, symmetric_OFB *ofb);
    int ofb_done(symmetric_OFB *ofb);
}

version(LTC_CBC_MODE)
{
    int cbc_start(int cipher, const ubyte *IV, const ubyte *key,
                   int keylen, int num_rounds, symmetric_CBC *cbc);
    int cbc_encrypt(const ubyte *pt, ubyte *ct, c_ulong len, symmetric_CBC *cbc);
    int cbc_decrypt(const ubyte *ct, ubyte *pt, c_ulong len, symmetric_CBC *cbc);
    int cbc_getiv(ubyte *IV, c_ulong *len, symmetric_CBC *cbc);
    int cbc_setiv(const ubyte *IV, c_ulong len, symmetric_CBC *cbc);
    int cbc_done(symmetric_CBC *cbc);
}

version(LTC_CTR_MODE)
{

    enum CTR_COUNTER_LITTLE_ENDIAN    = 0x0000;
    enum CTR_COUNTER_BIG_ENDIAN       = 0x1000;
    enum LTC_CTR_RFC3686              = 0x2000;
    
    int ctr_start(      int    cipher,
                  const ubyte* IV,
                  const ubyte* key,       
                        int    keylen,
                        int    num_rounds, 
                        int    ctr_mode,
                        symmetric_CTR *ctr);
    int ctr_encrypt(const ubyte *pt, ubyte *ct, c_ulong len, symmetric_CTR *ctr);
    int ctr_decrypt(const ubyte *ct, ubyte *pt, c_ulong len, symmetric_CTR *ctr);
    int ctr_getiv(ubyte *IV, c_ulong *len, symmetric_CTR *ctr);
    int ctr_setiv(const ubyte *IV, c_ulong len, symmetric_CTR *ctr);
    int ctr_done(symmetric_CTR *ctr);
    int ctr_test();
}

version(LTC_LRW_MODE)
{
    
    enum LRW_ENCRYPT = 0;
    enum LRW_DECRYPT = 1;

    int lrw_start(      int   cipher,
                  const ubyte *IV,
                  const ubyte *key,       
                        int    keylen,
                  const ubyte *tweak,
                        int    num_rounds, 
                       symmetric_LRW *lrw);
    int lrw_encrypt(const ubyte *pt, ubyte *ct, c_ulong len, symmetric_LRW *lrw);
    int lrw_decrypt(const ubyte *ct, ubyte *pt, c_ulong len, symmetric_LRW *lrw);
    int lrw_getiv(ubyte *IV, c_ulong *len, symmetric_LRW *lrw);
    int lrw_setiv(const ubyte *IV, c_ulong len, symmetric_LRW *lrw);
    int lrw_done(symmetric_LRW *lrw);
    int lrw_test();
    
    /* don't call */
    int lrw_process(const ubyte *pt, ubyte *ct, c_ulong len, int mode, symmetric_LRW *lrw);
}    

version(LTC_F8_MODE)
{
    int f8_start(      int   cipher, 
                 const ubyte *IV, 
                 const ubyte *key,                    int  keylen, 
                 const ubyte *salt_key,               int  skeylen,
                       int  num_rounds,               symmetric_F8  *f8);
    int f8_encrypt(const ubyte *pt, ubyte *ct, c_ulong len, symmetric_F8 *f8);
    int f8_decrypt(const ubyte *ct, ubyte *pt, c_ulong len, symmetric_F8 *f8);
    int f8_getiv(ubyte *IV, c_ulong *len, symmetric_F8 *f8);
    int f8_setiv(const ubyte *IV, c_ulong len, symmetric_F8 *f8);
    int f8_done(symmetric_F8 *f8);
    int f8_test_mode();
}

version(LTC_XTS_MODE)
{
    struct symmetric_xts
    {
       symmetric_key  key1, key2;
       int            cipher;
    } 

    int xts_start(      int  cipher,
                  const ubyte *key1, 
                  const ubyte *key2, 
                        c_ulong  keylen,
                        int  num_rounds, 
                        symmetric_xts *xts);
    
    int xts_encrypt(
       const ubyte *pt, c_ulong ptlen,
             ubyte *ct,
       const ubyte *tweak,
             symmetric_xts *xts);
    int xts_decrypt(
       const ubyte *ct, c_ulong ptlen,
             ubyte *pt,
       const ubyte *tweak,
             symmetric_xts *xts);
    
    void xts_done(symmetric_xts *xts);
    int  xts_test();
    void xts_mult_x(ubyte *I);
}

int find_cipher(const char *name);
int find_cipher_any(const char *name, int blocklen, int keylen);
int find_cipher_id(ubyte ID);
int register_cipher(const ltc_cipher_descriptor *cipher);
int unregister_cipher(const ltc_cipher_descriptor *cipher);
int cipher_is_valid(int idx);

mixin(LTC_MUTEX_PROTO("ltc_cipher_mutex"));

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_cipher.h,v $ */
/* $Revision: 1.54 $ */
/* $Date: 2007/05/12 14:37:41 $ */
