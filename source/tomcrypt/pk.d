/* ---- NUMBER THEORY ---- */
module tomcrypt.pk;

import core.stdc.config : c_ulong;
import core.stdc.stddef : wchar_t; 

import tomcrypt.prng;
import tomcrypt.pkcs;

extern(C) nothrow:

enum 
{
   PK_PUBLIC=0,
   PK_PRIVATE=1
}

int rand_prime(void *N, long len, prng_state *prng, int wprng);

/* ---- RSA ---- */
version(LTC_MRSA)
{

    /* Min and Max RSA key sizes (in bits) */
    enum MIN_RSA_SIZE = 1024;
    enum MAX_RSA_SIZE = 4096;
    
    /** RSA LTC_PKCS style key */
    struct rsa_key 
    {
        /** Type of key, PK_PRIVATE or PK_PUBLIC */
        int type;
        /** The public exponent */
        void *e; 
        /** The private exponent */
        void *d; 
        /** The modulus */
        void *N; 
        /** The p factor of N */
        void *p; 
        /** The q factor of N */
        void *q; 
        /** The 1/q mod p CRT param */
        void *qP; 
        /** The d mod (p - 1) CRT param */
        void *dP; 
        /** The d mod (q - 1) CRT param */
        void *dQ;
    }
    
    int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key);
    
    int rsa_exptmod(const ubyte* _in,   c_ulong inlen,
                          ubyte* _out,  c_ulong *outlen, int which,
                          rsa_key *key);
    
    void rsa_free(rsa_key *key);
    
    /* These use LTC_PKCS #1 v2.0 padding */
    int rsa_encrypt_key(const ubyte* _in,     c_ulong inlen,
                              ubyte* _out,    c_ulong *outlen,
                        const ubyte* lparam, c_ulong lparamlen,
                        prng_state *prng, int prng_idx, int hash_idx, rsa_key *key)
    {
       return rsa_encrypt_key_ex(_in, inlen, _out, outlen, lparam, lparamlen, prng, prng_idx, hash_idx, LTC_LTC_PKCS_1_OAEP, key);
    }
    
    int rsa_decrypt_key(const ubyte* _in,       c_ulong  inlen,
                                 ubyte* _out,      c_ulong *outlen,
                           const ubyte* lparam,    c_ulong  lparamlen,
                                 int               hash_idx,
                                 int              *stat,     rsa_key       *key)
    {
        return rsa_decrypt_key_ex(_in, inlen, _out, outlen, lparam, lparamlen, hash_idx, LTC_LTC_PKCS_1_OAEP, stat, key);
    }
    
    int rsa_sign_hash(const ubyte* _in,       c_ulong  inlen,
                               ubyte* _out,      c_ulong *outlen,
                               prng_state    *prng,     int            prng_idx,
                               int            hash_idx, c_ulong        saltlen,
                               rsa_key *key)
    {
        return rsa_sign_hash_ex(_in, inlen, _out, outlen, LTC_LTC_PKCS_1_PSS, prng, prng_idx, hash_idx, saltlen, key);
    }
    
    int rsa_verify_hash_ex(const ubyte* sig,      c_ulong siglen,
                           const ubyte* hash,     c_ulong hashlen,
                                 int            hash_idx, c_ulong       saltlen,
                                 int           *stat,     rsa_key      *key)
    {
        return rsa_verify_hash_ex(sig, siglen, hash, hashlen, LTC_LTC_PKCS_1_PSS, hash_idx, saltlen, stat, key);
    }
    
    /* These can be switched between LTC_PKCS #1 v2.x and LTC_PKCS #1 v1.5 paddings */
    int rsa_encrypt_key_ex(const ubyte* _in,     c_ulong inlen,
                                 ubyte* _out,    c_ulong *outlen,
                           const ubyte* lparam, c_ulong lparamlen,
                           prng_state *prng, int prng_idx, int hash_idx, int padding, rsa_key *key);
    
    int rsa_decrypt_key_ex(const ubyte* _in,       c_ulong  inlen,
                                 ubyte* _out,      c_ulong *outlen,
                           const ubyte* lparam,    c_ulong  lparamlen,
                                 int               hash_idx, int            padding,
                                 int              *stat,     rsa_key       *key);
    
    int rsa_sign_hash_ex(const ubyte* _in,       c_ulong  inlen,
                               ubyte* _out,      c_ulong *outlen,
                               int            padding,
                               prng_state    *prng,     int            prng_idx,
                               int            hash_idx, c_ulong        saltlen,
                               rsa_key *key);
    
    int rsa_verify_hash_ex(const ubyte* sig,      c_ulong siglen,
                           const ubyte* hash,     c_ulong hashlen,
                                 int            padding,
                                 int            hash_idx, c_ulong       saltlen,
                                 int           *stat,     rsa_key      *key);
    
    /* LTC_PKCS #1 import/export */
    int rsa_export(ubyte* _out, c_ulong *outlen, int type, rsa_key *key);
    int rsa_import(const ubyte* _in, c_ulong inlen, rsa_key *key);
                        
}

/* ---- Katja ---- */
version(MKAT)
{
    /* Min and Max KAT key sizes (in bits) */
    enum MIN_KAT_SIZE = 1024;
    enum MAX_KAT_SIZE = 4096;
    
    /** Katja LTC_PKCS style key */
    struct katja_key 
    {
        /** Type of key, PK_PRIVATE or PK_PUBLIC */
        int type;
        /** The private exponent */
        void *d; 
        /** The modulus */
        void *N; 
        /** The p factor of N */
        void *p; 
        /** The q factor of N */
        void *q; 
        /** The 1/q mod p CRT param */
        void *qP; 
        /** The d mod (p - 1) CRT param */
        void *dP; 
        /** The d mod (q - 1) CRT param */
        void *dQ;
        /** The pq param */
        void *pq;
    }
    
    int katja_make_key(prng_state *prng, int wprng, int size, katja_key *key);
    
    int katja_exptmod(const ubyte* _in,   c_ulong inlen,
                            ubyte* _out,  c_ulong *outlen, int which,
                            katja_key *key);
    
    void katja_free(katja_key *key);
    
    /* These use LTC_PKCS #1 v2.0 padding */
    int katja_encrypt_key(const ubyte* _in,     c_ulong inlen,
                                ubyte* _out,    c_ulong *outlen,
                          const ubyte* lparam, c_ulong lparamlen,
                          prng_state *prng, int prng_idx, int hash_idx, katja_key *key);
                                            
    int katja_decrypt_key(const ubyte* _in,       c_ulong  inlen,
                                ubyte* _out,      c_ulong *outlen, 
                          const ubyte* lparam,    c_ulong  lparamlen,
                                int            hash_idx, int *stat,
                                katja_key       *key);
    
    /* LTC_PKCS #1 import/export */
    int katja_export(ubyte* _out, c_ulong *outlen, int type, katja_key *key);
    int katja_import(const ubyte* _in, c_ulong inlen, katja_key *key);      
}

/* ---- ECC Routines ---- */
version(LTC_MECC)
{
    
    /* size of our temp buffers for exported keys */
    enum ECC_BUF_SIZE = 256;
    
    /* max private key size */
    enum ECC_MAXSIZE  = 66;
    
    /** Structure defines a NIST GF(p) curve */
    struct ltc_ecc_set_type
    {
       /** The size of the curve in octets */
       int size;
    
       /** name of curve */
       char *name; 
    
       /** The prime that defines the field the curve is in (encoded in hex) */
       char *prime;
    
       /** The fields B param (hex) */
       char *B;
    
       /** The order of the curve (hex) */
       char *order;
      
       /** The x co-ordinate of the base point on the curve (hex) */
       char *Gx;
     
       /** The y co-ordinate of the base point on the curve (hex) */
       char *Gy;
    }
    
    /** A point on a ECC curve, stored in Jacbobian format such that (x,y,z) => (x/z^2, y/z^3, 1) when interpretted as affine */
    struct ecc_point
    {
        /** The x co-ordinate */
        void *x;
    
        /** The y co-ordinate */
        void *y;
    
        /** The z co-ordinate */
        void *z;
    }
    
    /** An ECC key */
    struct ecc_key
    {
        /** Type of key, PK_PRIVATE or PK_PUBLIC */
        int type;
    
        /** Index into the ltc_ecc_sets[] for the parameters of this curve; if -1, then this key is using user supplied curve in dp */
        int idx;
    
        /** pointer to domain parameters; either points to NIST curves (identified by idx >= 0) or user supplied curve */
        const ltc_ecc_set_type *dp;
    
        /** The public key */
        ecc_point pubkey;
    
        /** The private key */
        void *k;
    }
    
    /** the ECC params provided */
    extern const __gshared ltc_ecc_set_type[] ltc_ecc_sets;
    
    int  ecc_test();
    void ecc_sizes(int *low, int *high);
    int  ecc_get_size(ecc_key *key);
    
    int  ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key);
    int  ecc_make_key_ex(prng_state *prng, int wprng, ecc_key *key, const ltc_ecc_set_type *dp);
    void ecc_free(ecc_key *key);
    
    int  ecc_export(ubyte* _out, c_ulong *outlen, int type, ecc_key *key);
    int  ecc_import(const ubyte* _in, c_ulong inlen, ecc_key *key);
    int  ecc_import_ex(const ubyte* _in, c_ulong inlen, ecc_key *key, const ltc_ecc_set_type *dp);
    
    int ecc_ansi_x963_export(ecc_key *key, ubyte* _out, c_ulong *outlen);
    int ecc_ansi_x963_import(const ubyte* _in, c_ulong inlen, ecc_key *key);
    int ecc_ansi_x963_import_ex(const ubyte* _in, c_ulong inlen, ecc_key *key, ltc_ecc_set_type *dp);
    
    int  ecc_shared_secret(ecc_key *private_key, ecc_key *public_key, 
                           ubyte* _out, c_ulong *outlen);
    
    int  ecc_encrypt_key(const ubyte* _in,   c_ulong inlen,
                               ubyte* _out,  c_ulong *outlen, 
                               prng_state *prng, int wprng, int hash, 
                               ecc_key *key);
    
    int  ecc_decrypt_key(const ubyte* _in,  c_ulong  inlen,
                               ubyte* _out, c_ulong *outlen, 
                               ecc_key *key);
    
    int  ecc_sign_hash(const ubyte* _in,  c_ulong inlen, 
                             ubyte* _out, c_ulong *outlen, 
                             prng_state *prng, int wprng, ecc_key *key);
    
    int  ecc_verify_hash(const ubyte* sig,  c_ulong siglen,
                         const ubyte* hash, c_ulong hashlen, 
                         int *stat, ecc_key *key);
    
    /* low level functions */
    ecc_point *ltc_ecc_new_point();
    void       ltc_ecc_del_point(ecc_point *p);
    int        ltc_ecc_is_valid_idx(int n);
    
    /* point ops (mp == montgomery digit) */
    version(LTM_LTC_DESC)
    {
        /* R = 2P */
        int ltc_ecc_projective_dbl_point(ecc_point *P, ecc_point *R, void *modulus, void *mp);
        
        /* R = P + Q */
        int ltc_ecc_projective_add_point(ecc_point *P, ecc_point *Q, ecc_point *R, void *modulus, void *mp);        
    }
    else version(GMP_LTC_DESC)
    {
        /* R = 2P */
        int ltc_ecc_projective_dbl_point(ecc_point *P, ecc_point *R, void *modulus, void *mp);
        
        /* R = P + Q */
        int ltc_ecc_projective_add_point(ecc_point *P, ecc_point *Q, ecc_point *R, void *modulus, void *mp);        
    }
    else version(LTC_MECC_ACCEL) {}
    else
    {
        /* R = 2P */
        int ltc_ecc_projective_dbl_point(ecc_point *P, ecc_point *R, void *modulus, void *mp);
        
        /* R = P + Q */
        int ltc_ecc_projective_add_point(ecc_point *P, ecc_point *Q, ecc_point *R, void *modulus, void *mp);        
    }
    
    version(LTC_MECC_FP)
    {
        /* optimized point multiplication using fixed point cache (HAC algorithm 14.117) */
        int ltc_ecc_fp_mulmod(void *k, ecc_point *G, ecc_point *R, void *modulus, int map);
        
        /* functions for saving/loading/freeing/adding to fixed point cache */
        int ltc_ecc_fp_save_state(ubyte* *_out, c_ulong *outlen);
        int ltc_ecc_fp_restore_state(ubyte* _in, c_ulong inlen);
        void ltc_ecc_fp_free();
        int ltc_ecc_fp_add_point(ecc_point *g, void *modulus, int lock);
        
        /* lock/unlock all points currently in fixed point cache */
        void ltc_ecc_fp_tablelock(int lock);
    }
    
    /* R = kG */
    int ltc_ecc_mulmod(void *k, ecc_point *G, ecc_point *R, void *modulus, int map);
    
    version(LTC_ECC_SHAMIR)
    {
        /* kA*A + kB*B = C */
        int ltc_ecc_mul2add(ecc_point *A, void *kA,
                            ecc_point *B, void *kB,
                            ecc_point *C,
                                 void *modulus);
    
        version(LTC_MECC_FP)
        {
        /* Shamir's trick with optimized point multiplication using fixed point cache */
        int ltc_ecc_fp_mul2add(ecc_point *A, void *kA,
                               ecc_point *B, void *kB,
                               ecc_point *C, void *modulus);
        }
    }
    
    
    /* map P to affine from projective */
    int ltc_ecc_map(ecc_point *P, void *modulus, void *mp);
}

version(LTC_MDSA)
{

    /* Max diff between group and modulus size in bytes */
    enum LTC_MDSA_DELTA     = 512;
    
    /* Max DSA group size in bytes (default allows 4k-bit groups) */
    enum LTC_MDSA_MAX_GROUP = 512;
    
    /** DSA key structure */
    struct dsa_key
    {
       /** The key type, PK_PRIVATE or PK_PUBLIC */
       int type; 
    
       /** The order of the sub-group used in octets */
       int qord;
    
       /** The generator  */
       void *g;
    
       /** The prime used to generate the sub-group */
       void *q;
    
       /** The large prime that generats the field the contains the sub-group */
       void *p;
    
       /** The private key */
       void *x;
    
       /** The public key */
       void *y;
    }
    
    int dsa_make_key(prng_state *prng, int wprng, int group_size, int modulus_size, dsa_key *key);
    void dsa_free(dsa_key *key);
    
    int dsa_sign_hash_raw(const ubyte* _in,  c_ulong inlen,
                                       void *r,   void *s,
                                   prng_state *prng, int wprng, dsa_key *key);
    
    int dsa_sign_hash(const ubyte* _in,  c_ulong inlen,
                            ubyte* _out, c_ulong *outlen,
                            prng_state *prng, int wprng, dsa_key *key);
    
    int dsa_verify_hash_raw(         void *r,          void *s,
                        const ubyte* hash, c_ulong hashlen, 
                                        int *stat,      dsa_key *key);
    
    int dsa_verify_hash(const ubyte* sig,  c_ulong siglen,
                        const ubyte* hash, c_ulong hashlen, 
                              int           *stat, dsa_key       *key);
    
    int dsa_encrypt_key(const ubyte* _in,   c_ulong inlen,
                              ubyte* _out,  c_ulong *outlen, 
                              prng_state *prng, int wprng, int hash, 
                              dsa_key *key);
                          
    int dsa_decrypt_key(const ubyte* _in,  c_ulong  inlen,
                              ubyte* _out, c_ulong *outlen, 
                              dsa_key *key);
                              
    int dsa_import(const ubyte* _in, c_ulong inlen, dsa_key *key);
    int dsa_export(ubyte* _out, c_ulong *outlen, int type, dsa_key *key);
    int dsa_verify_key(dsa_key *key, int *stat);
    
    int dsa_shared_secret(void          *private_key, void *base,
                          dsa_key       *public_key,
                          ubyte* _out,         c_ulong *outlen);
}

version(LTC_DER)
{
    /* DER handling */
    
    enum 
    {
     LTC_ASN1_EOL,
     LTC_ASN1_BOOLEAN,
     LTC_ASN1_INTEGER,
     LTC_ASN1_SHORT_INTEGER,
     LTC_ASN1_BIT_STRING,
     LTC_ASN1_OCTET_STRING,
     LTC_ASN1_NULL,
     LTC_ASN1_OBJECT_IDENTIFIER,
     LTC_ASN1_IA5_STRING,
     LTC_ASN1_PRINTABLE_STRING,
     LTC_ASN1_UTF8_STRING,
     LTC_ASN1_UTCTIME,
     LTC_ASN1_CHOICE,
     LTC_ASN1_SEQUENCE,
     LTC_ASN1_SET,
     LTC_ASN1_SETOF
    }
    
    /** A LTC ASN.1 list type */
    struct ltc_asn1_list 
    {
       /** The LTC ASN.1 enumerated type identifier */
       int           type;
       /** The data to encode or place for decoding */
       void         *data;
       /** The size of the input or resulting output */
       c_ulong size;
       /** The used flag, this is used by the CHOICE ASN.1 type to indicate which choice was made */
       int           used;
       /** prev/next entry in the list */
       ltc_asn1_list* prev, next, child, parent;
    } 
    
    void LTC_SET_ASN1(ltc_asn1_list* list, int index, int Type, void* Data, c_ulong Size)
    {                            
        int LTC_MACRO_temp            = index;       
        ltc_asn1_list* LTC_MACRO_list = list;        
        LTC_MACRO_list[LTC_MACRO_temp].type = Type;  
        LTC_MACRO_list[LTC_MACRO_temp].data = Data;  
        LTC_MACRO_list[LTC_MACRO_temp].size = Size;  
        LTC_MACRO_list[LTC_MACRO_temp].used = 0;      
    } 
    
    /* SEQUENCE */
    int der_encode_sequence_ex(ltc_asn1_list *list, c_ulong inlen,
                               ubyte* _out,         c_ulong *outlen, int type_of);
    
    int der_encode_sequence_ex(ltc_asn1_list *list, c_ulong inlen,
                                   ubyte* _out,     c_ulong *outlen)
    {
        return der_encode_sequence_ex(list, inlen, _out, outlen, LTC_ASN1_SEQUENCE);
    }    
    
    int der_decode_sequence_ex(const ubyte* _in,        c_ulong  inlen,
                               ltc_asn1_list *list,     c_ulong  outlen, int ordered);
    
    int der_decode_sequence(const ubyte* _in,        c_ulong  inlen,
                               ltc_asn1_list *list,     c_ulong  outlen)                          
    {
        return der_decode_sequence_ex(_in, inlen, list, outlen, 1);
    }
    
    int der_length_sequence(ltc_asn1_list *list, c_ulong inlen,
                            c_ulong *outlen);
    
    /* SET */
    int der_decode_set(const ubyte* _in,        c_ulong  inlen,
                               ltc_asn1_list *list,     c_ulong  outlen)
    {
        return der_decode_sequence_ex(_in, inlen, list, outlen, 0);
    }

    alias der_length_set = der_length_sequence;
    int der_encode_set(ltc_asn1_list *list, c_ulong inlen,
                       ubyte* _out,  c_ulong *outlen);
    
    int der_encode_setof(ltc_asn1_list *list, c_ulong inlen,
                         ubyte* _out,  c_ulong *outlen);
                            
    /* VA list handy helpers with triplets of <type, size, data> */
    int der_encode_sequence_multi(ubyte* _out, c_ulong *outlen, ...);
    int der_decode_sequence_multi(const ubyte* _in, c_ulong inlen, ...);
    
    /* FLEXI DECODER handle unknown list decoder */
    int  der_decode_sequence_flexi(const ubyte* _in, c_ulong *inlen, ltc_asn1_list **_out);
    void der_free_sequence_flexi(ltc_asn1_list *list);
    void der_sequence_free(ltc_asn1_list *_in);
    
    /* BOOLEAN */
    int der_length_boolean(c_ulong *outlen);
    int der_encode_boolean(int _in, 
                           ubyte* _out, c_ulong *outlen);
    int der_decode_boolean(const ubyte* _in, c_ulong inlen,
                                           int *_out);              
    /* INTEGER */
    int der_encode_integer(void *num, ubyte* _out, c_ulong *outlen);
    int der_decode_integer(const ubyte* _in, c_ulong inlen, void *num);
    int der_length_integer(void *num, c_ulong *len);
    
    /* INTEGER -- handy for 0..2^32-1 values */
    int der_decode_short_integer(const ubyte* _in, c_ulong inlen, c_ulong *num);
    int der_encode_short_integer(c_ulong num, ubyte* _out, c_ulong *outlen);
    int der_length_short_integer(c_ulong num, c_ulong *outlen);
    
    /* BIT STRING */
    int der_encode_bit_string(const ubyte* _in, c_ulong inlen,
                                    ubyte* _out, c_ulong *outlen);
    int der_decode_bit_string(const ubyte* _in, c_ulong inlen,
                                    ubyte* _out, c_ulong *outlen);
    int der_length_bit_string(c_ulong nbits, c_ulong *outlen);
    
    /* OCTET STRING */
    int der_encode_octet_string(const ubyte* _in, c_ulong inlen,
                                      ubyte* _out, c_ulong *outlen);
    int der_decode_octet_string(const ubyte* _in, c_ulong inlen,
                                      ubyte* _out, c_ulong *outlen);
    int der_length_octet_string(c_ulong noctets, c_ulong *outlen);
    
    /* OBJECT IDENTIFIER */
    int der_encode_object_identifier(c_ulong *words, c_ulong  nwords,
                                     ubyte* _out,   c_ulong *outlen);
    int der_decode_object_identifier(const ubyte* _in,    c_ulong  inlen,
                                           c_ulong *words, c_ulong *outlen);
    int der_length_object_identifier(c_ulong *words, c_ulong nwords, c_ulong *outlen);
    c_ulong der_object_identifier_bits(c_ulong x);
    
    /* IA5 STRING */
    int der_encode_ia5_string(const ubyte* _in, c_ulong inlen,
                                    ubyte* _out, c_ulong *outlen);
    int der_decode_ia5_string(const ubyte* _in, c_ulong inlen,
                                    ubyte* _out, c_ulong *outlen);
    int der_length_ia5_string(const ubyte* octets, c_ulong noctets, c_ulong *outlen);
    
    int der_ia5_char_encode(int c);
    int der_ia5_value_decode(int v);
    
    /* Printable STRING */
    int der_encode_printable_string(const ubyte* _in, c_ulong inlen,
                                    ubyte* _out, c_ulong *outlen);
    int der_decode_printable_string(const ubyte* _in, c_ulong inlen,
                                    ubyte* _out, c_ulong *outlen);
    int der_length_printable_string(const ubyte* octets, c_ulong noctets, c_ulong *outlen);
    
    int der_printable_char_encode(int c);
    int der_printable_value_decode(int v);
    
    /* UTF-8 */
    
    int der_encode_utf8_string(const wchar_t *_in,  c_ulong inlen,
                               ubyte* _out, c_ulong *outlen);
    
    int der_decode_utf8_string(const ubyte* _in,  c_ulong inlen,
                                           wchar_t *_out, c_ulong *outlen);
    c_ulong der_utf8_charsize(const wchar_t c);
    int der_length_utf8_string(const wchar_t *_in, c_ulong noctets, c_ulong *outlen);
    
    
    /* CHOICE */
    int der_decode_choice(const ubyte* _in,   c_ulong *inlen,
                                ltc_asn1_list *list, c_ulong  outlen);
    
    /* UTCTime */
    struct ltc_utctime 
    {
       uint     YY, /* year */
                MM, /* month */
                DD, /* day */
                hh, /* hour */
                mm, /* minute */
                ss, /* second */
                off_dir, /* timezone offset direction 0 == +, 1 == - */
                off_hh, /* timezone offset hours */
                off_mm; /* timezone offset minutes */
    }
    
    int der_encode_utctime(ltc_utctime *utctime, 
                           ubyte* _out,   c_ulong *outlen);
    
    int der_decode_utctime(const ubyte* _in, c_ulong *inlen,
                                 ltc_utctime   *_out);
    
    int der_length_utctime(ltc_utctime *utctime, c_ulong *outlen);
}

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_pk.h,v $ */
/* $Revision: 1.81 $ */
/* $Date: 2007/05/12 14:32:35 $ */