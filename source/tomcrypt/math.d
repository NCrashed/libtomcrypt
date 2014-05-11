/** math functions **/
module tomcrypt.math;

import core.stdc.config;
import tomcrypt.prng;
import tomcrypt.pk;

extern(C) nothrow:

enum LTC_MP_LT   = -1;
enum LTC_MP_EQ   = 0;
enum LTC_MP_GT   = 1;

enum LTC_MP_NO   = 0;
enum LTC_MP_YES  = 1;

version(LTC_MECC) {}
else
{
   alias void ecc_point;
}

version(LTC_MRSA) {}
else
{
   alias void rsa_key;
}

/** math descriptor */
struct ltc_math_descriptor
{
   /** Name of the math provider */
   char *name;

   /** Bits per digit, amount of bits must fit in an c_ulong */
   int  bits_per_digit;

/* ---- init/deinit functions ---- */

   /** initialize a bignum
     @param   a     The number to initialize
     @return  CRYPT_OK on success
   */
   int function(void **a) nothrow init;
   
   /** init copy 
     @param  dst    The number to initialize and write to
     @param  src    The number to copy from
     @return CRYPT_OK on success
   */
   int function(void **dst, void *src) nothrow init_copy;

   /** deinit 
      @param   a    The number to free
      @return CRYPT_OK on success
   */
   void function(void *a) nothrow deinit;

/* ---- data movement ---- */

   /** negate
      @param   src   The number to negate
      @param   dst   The destination
      @return CRYPT_OK on success
   */
   int function(void *src, void *dst) nothrow neg;
   
   /** copy 
      @param   src   The number to copy from
      @param   dst   The number to write to 
      @return CRYPT_OK on success
   */
   int function(void *src, void *dst) nothrow copy;

/* ---- trivial low level functions ---- */

   /** set small constant 
      @param a    Number to write to
      @param n    Source upto bits_per_digit (actually meant for very small constants) 
      @return CRYPT_OK on succcess
   */
   int function(void *a, c_ulong n) nothrow set_int;

   /** get small constant 
      @param a    Number to read, only fetches upto bits_per_digit from the number
      @return  The lower bits_per_digit of the integer (unsigned)
   */
   c_ulong function(void *a) nothrow get_int;

   /** get digit n 
     @param a  The number to read from
     @param n  The number of the digit to fetch
     @return  The bits_per_digit  sized n'th digit of a
   */
   c_ulong function(void *a, int n) nothrow get_digit;

   /** Get the number of digits that represent the number
     @param a   The number to count
     @return The number of digits used to represent the number
   */
   int function(void *a) nothrow get_digit_count;

   /** compare two integers
     @param a   The left side integer
     @param b   The right side integer
     @return LTC_MP_LT if a < b, LTC_MP_GT if a > b and LTC_MP_EQ otherwise.  (signed comparison)
   */
   int function(void *a, void *b) nothrow compare;

   /** compare against int 
     @param a   The left side integer
     @param b   The right side integer (upto bits_per_digit)
     @return LTC_MP_LT if a < b, LTC_MP_GT if a > b and LTC_MP_EQ otherwise.  (signed comparison)
   */
   int function(void *a, c_ulong n) nothrow compare_d;

   /** Count the number of bits used to represent the integer
     @param a   The integer to count
     @return The number of bits required to represent the integer
   */
   int function(void * a) nothrow count_bits;

   /** Count the number of LSB bits which are zero 
     @param a   The integer to count
     @return The number of contiguous zero LSB bits
   */
   int function(void *a) nothrow count_lsb_bits;

   /** Compute a power of two
     @param a  The integer to store the power in
     @param n  The power of two you want to store (a = 2^n)
     @return CRYPT_OK on success
   */
   int function(void *a , int n) nothrow twoexpt;

/* ---- radix conversions ---- */
   
   /** read ascii string 
     @param a     The integer to store into
     @param str   The string to read
     @param radix The radix the integer has been represented in (2-64)
     @return CRYPT_OK on success
   */
   int function(void *a, const char *str, int radix) nothrow read_radix;

   /** write number to string
     @param a     The integer to store
     @param str   The destination for the string
     @param radix The radix the integer is to be represented in (2-64)
     @return CRYPT_OK on success
   */
   int function(void *a, char *str, int radix) nothrow write_radix;

   /** get size as unsigned char string 
     @param a     The integer to get the size (when stored in array of octets)
     @return The length of the integer
   */
   c_ulong function(void *a) nothrow unsigned_size;

   /** store an integer as an array of octets 
     @param src   The integer to store
     @param dst   The buffer to store the integer in
     @return CRYPT_OK on success
   */
   int function(void *src, ubyte* dst) nothrow unsigned_write;

   /** read an array of octets and store as integer
     @param dst   The integer to load
     @param src   The array of octets 
     @param len   The number of octets 
     @return CRYPT_OK on success
   */
   int function(void *dst, ubyte* src, c_ulong len) nothrow unsigned_read;

/* ---- basic math ---- */

   /** add two integers 
     @param a   The first source integer
     @param b   The second source integer
     @param c   The destination of "a + b"
     @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c) nothrow add;


   /** add two integers 
     @param a   The first source integer
     @param b   The second source integer (single digit of upto bits_per_digit in length)
     @param c   The destination of "a + b"
     @return CRYPT_OK on success
   */
   int function(void *a, c_ulong b, void *c) nothrow addi;

   /** subtract two integers 
     @param a   The first source integer
     @param b   The second source integer
     @param c   The destination of "a - b"
     @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c) nothrow sub;

   /** subtract two integers 
     @param a   The first source integer
     @param b   The second source integer (single digit of upto bits_per_digit in length)
     @param c   The destination of "a - b"
     @return CRYPT_OK on success
   */
   int function(void *a, c_ulong b, void *c) nothrow subi;

   /** multiply two integers 
     @param a   The first source integer
     @param b   The second source integer (single digit of upto bits_per_digit in length)
     @param c   The destination of "a * b"
     @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c) nothrow mul;

   /** multiply two integers 
     @param a   The first source integer
     @param b   The second source integer (single digit of upto bits_per_digit in length)
     @param c   The destination of "a * b"
     @return CRYPT_OK on success
   */
   int function(void *a, c_ulong b, void *c) nothrow muli;

   /** Square an integer
     @param a    The integer to square
     @param b    The destination
     @return CRYPT_OK on success
   */
   int function(void *a, void *b) nothrow sqr;

   /** Divide an integer
     @param a    The dividend
     @param b    The divisor
     @param c    The quotient (can be NULL to signify don't care)
     @param d    The remainder (can be NULL to signify don't care)
     @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c, void *d) nothrow mpdiv;

   /** divide by two 
      @param  a   The integer to divide (shift right)
      @param  b   The destination 
      @return CRYPT_OK on success
   */
   int function(void *a, void *b) nothrow div_2;

   /** Get remainder (small value)
      @param  a    The integer to reduce
      @param  b    The modulus (upto bits_per_digit in length)
      @param  c    The destination for the residue
      @return CRYPT_OK on success
   */
   int function(void *a, c_ulong b, c_ulong *c) nothrow modi;

   /** gcd 
      @param  a     The first integer
      @param  b     The second integer
      @param  c     The destination for (a, b)
      @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c) nothrow gcd;

   /** lcm 
      @param  a     The first integer
      @param  b     The second integer
      @param  c     The destination for [a, b]
      @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c) nothrow lcm;

   /** Modular multiplication
      @param  a     The first source
      @param  b     The second source 
      @param  c     The modulus
      @param  d     The destination (a*b mod c)
      @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c, void *d) nothrow mulmod;

   /** Modular squaring
      @param  a     The first source
      @param  b     The modulus
      @param  c     The destination (a*a mod b)
      @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c) nothrow sqrmod;

   /** Modular inversion
      @param  a     The value to invert
      @param  b     The modulus 
      @param  c     The destination (1/a mod b)
      @return CRYPT_OK on success
   */
   int function(void *, void *, void *) nothrow invmod;

/* ---- reduction ---- */

   /** setup montgomery
       @param a  The modulus 
       @param b  The destination for the reduction digit 
       @return CRYPT_OK on success
   */
   int function(void *a, void **b) nothrow montgomery_setup;

   /** get normalization value 
       @param a   The destination for the normalization value
       @param b   The modulus
       @return  CRYPT_OK on success
   */
   int function(void *a, void *b) nothrow montgomery_normalization;

   /** reduce a number
       @param a   The number [and dest] to reduce
       @param b   The modulus
       @param c   The value "b" from montgomery_setup()
       @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c) nothrow montgomery_reduce;

   /** clean up  (frees memory)
       @param a   The value "b" from montgomery_setup()
       @return CRYPT_OK on success
   */      
   void function(void *a) nothrow montgomery_deinit;

/* ---- exponentiation ---- */

   /** Modular exponentiation
       @param a    The base integer
       @param b    The power (can be negative) integer
       @param c    The modulus integer
       @param d    The destination
       @return CRYPT_OK on success
   */
   int function(void *a, void *b, void *c, void *d) nothrow exptmod;

   /** Primality testing
       @param a     The integer to test
       @param b     The destination of the result (FP_YES if prime)
       @return CRYPT_OK on success
   */
   int function(void *a, int *b) nothrow isprime;

/* ----  (optional) ecc point math ---- */

   /** ECC GF(p) point multiplication (from the NIST curves)
       @param k   The integer to multiply the point by
       @param G   The point to multiply
       @param R   The destination for kG  
       @param modulus  The modulus for the field
       @param map Boolean indicated whether to map back to affine or not (can be ignored if you work in affine only)
       @return CRYPT_OK on success
   */
   int function(void *k, ecc_point *G, ecc_point *R, void *modulus, int map) nothrow ecc_ptmul;

   /** ECC GF(p) point addition 
       @param P    The first point
       @param Q    The second point
       @param R    The destination of P + Q
       @param modulus  The modulus
       @param mp   The "b" value from montgomery_setup()
       @return CRYPT_OK on success
   */
   int function(ecc_point *P, ecc_point *Q, ecc_point *R, void *modulus, void *mp) nothrow ecc_ptadd;

   /** ECC GF(p) point double 
       @param P    The first point
       @param R    The destination of 2P
       @param modulus  The modulus
       @param mp   The "b" value from montgomery_setup()
       @return CRYPT_OK on success
   */
   int function(ecc_point *P, ecc_point *R, void *modulus, void *mp) nothrow ecc_ptdbl;

   /** ECC mapping from projective to affine, currently uses (x,y,z) => (x/z^2, y/z^3, 1)
       @param P     The point to map
       @param modulus The modulus
       @param mp    The "b" value from montgomery_setup()
       @return CRYPT_OK on success
       @remark  The mapping can be different but keep in mind a ecc_point only has three 
                integers (x,y,z) so if you use a different mapping you have to make it fit.
   */
   int function(ecc_point *P, void *modulus, void *mp) nothrow ecc_map;

   /** Computes kA*A + kB*B = C using Shamir's Trick
       @param A        First point to multiply
       @param kA       What to multiple A by
       @param B        Second point to multiply
       @param kB       What to multiple B by
       @param C        [out] Destination point (can overlap with A or B
       @param modulus  Modulus for curve 
       @return CRYPT_OK on success
   */ 
   int function(ecc_point *A, void *kA,
           ecc_point *B, void *kB,
           ecc_point *C,
           void *modulus) nothrow ecc_mul2add;

/* ---- (optional) rsa optimized math (for internal CRT) ---- */

   /** RSA Key Generation 
       @param prng     An active PRNG state
       @param wprng    The index of the PRNG desired
       @param size     The size of the modulus (key size) desired (octets)
       @param e        The "e" value (public key).  e==65537 is a good choice
       @param key      [out] Destination of a newly created private key pair
       @return CRYPT_OK if successful, upon error all allocated ram is freed
    */
    int function(prng_state *prng, int wprng, int size, long e, rsa_key *key) nothrow rsa_keygen;
   

   /** RSA exponentiation
      @param in       The octet array representing the base
      @param inlen    The length of the input
      @param out      The destination (to be stored in an octet array format)
      @param outlen   The length of the output buffer and the resulting size (zero padded to the size of the modulus)
      @param which    PK_PUBLIC for public RSA and PK_PRIVATE for private RSA
      @param key      The RSA key to use 
      @return CRYPT_OK on success
   */
   int function(const ubyte* _in,   c_ulong inlen,
                       ubyte* _out,  c_ulong *outlen, int which,
                       rsa_key *key) nothrow rsa_me;
}

extern __gshared ltc_math_descriptor ltc_mp;

int ltc_init_multi(void **a, ...);
void ltc_deinit_multi(void *a, ...);

version(LTM_DESC)
{
    extern const __gshared ltc_math_descriptor ltm_desc;
}

version(TFM_DESC)
{
    extern const __gshared ltc_math_descriptor tfm_desc;
}

version(GMP_DESC)
{
    extern const __gshared ltc_math_descriptor gmp_desc;
}

version(DESC_DEF_ONLY) {}
else version(LTC_SOURCE)
{

    alias MP_DIGIT_BIT                 = ltc_mp.bits_per_digit;
    
    /* some handy macros */
    int mp_init(void **a)                   { return ltc_mp.init(a); }
    alias mp_init_multi                     = ltc_init_multi;
    void mp_clear(void *a)                  { ltc_mp.deinit(a); }
    alias mp_clear_multi                    = ltc_deinit_multi;
    int mp_init_copy(void **dst, void *src) { return ltc_mp.init_copy(dst, src); }
    
    int mp_neg(void *src, void *dst)   { return ltc_mp.neg(src, dst); }
    int mp_copy(void *src, void *dst)  { return ltc_mp.copy(src, dst); }
    
    int mp_set(void *a, c_ulong n)     { return ltc_mp.set_int(a, n); } 
    alias mp_set_int                   = mp_set;
    
    c_ulong mp_get_int(void *a)          { return ltc_mp.get_int(a); } 
    c_ulong mp_get_digit(void *a, int n) { return ltc_mp.get_digit(a, n); }
    int mp_get_digit_count(void *a)      { return ltc_mp.get_digit_count(a); }
    int mp_cmp(void *a, void *b)         { return ltc_mp.compare(a, b); }
    int mp_cmp_d(void *a, c_ulong n)       { return ltc_mp.compare_d(a, n); }
    int mp_count_bits(void * a)          { return ltc_mp.count_bits(a); }
    int mp_cnt_lsb(void *a)              { return ltc_mp.count_lsb_bits(a); }
    int mp_2expt(void *a , int n)        { return ltc_mp.twoexpt(a, n); }

    int mp_read_radix(void *a, const char *str, int radix)       { return ltc_mp.read_radix(a, str, radix); }
    int mp_toradix(void *a, char *str, int radix)                { return ltc_mp.write_radix(a, str, radix); }
    c_ulong mp_unsigned_bin_size(void *a)                        { return ltc_mp.unsigned_size(a); }
    int mp_to_unsigned_bin(void *src, ubyte* dst)                { return ltc_mp.unsigned_write(src, dst); }
    int mp_read_unsigned_bin(void *dst, ubyte* src, c_ulong len) { return ltc_mp.unsigned_read(dst, src, len); }
   
    int mp_add(void *a, void *b, void *c)               { return ltc_mp.add(a, b, c); }
    int mp_add_d(void *a, c_ulong b, void *c)           { return ltc_mp.addi(a, b, c); }
    int mp_sub(void *a, void *b, void *c)               { return ltc_mp.sub(a, b, c); }
    int mp_sub_d(void *a, c_ulong b, void *c)           { return ltc_mp.subi(a, b, c); }
    int mp_mul(void *a, void *b, void *c)               { return ltc_mp.mul(a, b, c); }
    int mp_mul_d(void *a, c_ulong b, void *c)           { return ltc_mp.muli(a, b, c); }
    int mp_sqr(void *a, void *b)                        { return ltc_mp.sqr(a, b); }
    int mp_div(void *a, void *b, void *c, void *d)      { return ltc_mp.mpdiv(a, b, c, d); }
    int mp_div_2(void *a, void *b)                      { return ltc_mp.div_2(a, b); }
    int mp_mod(void *a, void *b, void *c)               { return ltc_mp.mpdiv(a, b, null, c);} 
    int mp_mod_d(void *a, c_ulong b, c_ulong *c)        { return ltc_mp.modi(a, b, c); }
    int mp_gcd(void *a, void *b, void *c)               { return ltc_mp.gcd(a, b, c); }
    int mp_lcm(void *a, void *b, void *c)               { return ltc_mp.lcm(a, b, c); }
    
    int mp_mulmod(void *a, void *b, void *c, void *d)   { return ltc_mp.mulmod(a, b, c, d); }
    int mp_sqrmod(void *a, void *b, void *c)            { return ltc_mp.sqrmod(a, b, c); }
    int mp_invmod(void *a, void *b, void *c)            { return ltc_mp.invmod(a, b, c); }
    
    int mp_montgomery_setup(void *a, void **b)          { return ltc_mp.montgomery_setup(a, b);}
    int mp_montgomery_normalization(void *a, void *b)   { return ltc_mp.montgomery_normalization(a, b);}
    int mp_montgomery_reduce(void *a, void *b, void *c) { return ltc_mp.montgomery_reduce(a, b, c);}   
    void mp_montgomery_free(void *a)                    { return ltc_mp.montgomery_deinit(a);}
    
    int mp_exptmod(void *a, void *b, void *c, void *d)  { return ltc_mp.exptmod(a, b, c, d);}
    int mp_prime_is_prime(void *a, int *b)              { return ltc_mp.isprime(a, b);}
    
    bool mp_iszero(void* a)           {return (mp_cmp_d(a, 0) == LTC_MP_EQ ? LTC_MP_YES : LTC_MP_NO);}
    bool mp_isodd(void *a)            {return (mp_get_digit_count(a) > 0 ? (mp_get_digit(a, 0) & 1 ? LTC_MP_YES : LTC_MP_NO) : LTC_MP_NO);}
    void mp_exch(T)(T a, T b)         {void *ABC__tmp = a; a = b; b = ABC__tmp;}
    
    int mp_tohex(void *a, char *str) {return mp_toradix(a, str, 16);}
}

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_math.h,v $ */
/* $Revision: 1.44 $ */
/* $Date: 2007/05/12 14:32:35 $ */