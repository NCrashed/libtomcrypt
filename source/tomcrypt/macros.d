/* ---- HELPER MACROS ---- */
module tomcrypt.macros;

version(ENDIAN_NEUTRAL)
{
    void STORE32L(uint x, ref ubyte[4] y)
    {
        y[3] = cast(ubyte)((x>>24)&255); y[2] = cast(ubyte)((x>>16)&255);   
        y[1] = cast(ubyte)((x>>8 )&255); y[0] = cast(ubyte)( x     &255);
    }
    
    void LOAD32L(ref uint x, ref ubyte[4] y)
    {
        x = (cast(uint)(y[3] & 255)<<24) | 
            (cast(uint)(y[2] & 255)<<16) | 
            (cast(uint)(y[1] & 255)<<8)  | 
            (cast(uint)(y[0] & 255));
    }
    
    void STORE64L(ulong x, ref ubyte[8] y)
    {
        y[7] = cast(ubyte)((x>>56)&255); y[6] = cast(ubyte)((x>>48)&255);   
        y[5] = cast(ubyte)((x>>40)&255); y[4] = cast(ubyte)((x>>32)&255);   
        y[3] = cast(ubyte)((x>>24)&255); y[2] = cast(ubyte)((x>>16)&255);   
        y[1] = cast(ubyte)((x>>8)&255);  y[0] = cast(ubyte)(x&255); 
    }
    
    void LOAD64L(ref ulong x, ref ubyte[8] y)
    {
        x = ((cast(ulong)(y[7] & 255))<<56)|((cast(ulong)(y[6] & 255))<<48)| 
            ((cast(ulong)(y[5] & 255))<<40)|((cast(ulong)(y[4] & 255))<<32)| 
            ((cast(ulong)(y[3] & 255))<<24)|((cast(ulong)(y[2] & 255))<<16)| 
            ((cast(ulong)(y[1] & 255))<<8 )|((cast(ulong)(y[0] & 255)));
    }
    
    void STORE32H(uint x, ref ubyte[4] y)
    {
        y[0] = cast(ubyte)((x>>24)&255); y[1] = cast(ubyte)((x>>16)&255);   
        y[2] = cast(ubyte)((x>>8 )&255); y[3] = cast(ubyte)( x     &255); 
    }
    
    void LOAD32H(ref uint x, ref ubyte[4] y)
    {
        x = (cast(uint)(y[0] & 255)<<24) |
            (cast(uint)(y[1] & 255)<<16) |
            (cast(uint)(y[2] & 255)<<8)  |
            (cast(uint)(y[3] & 255));
    }
    
    void STORE64H(ulong x, ref ubyte[8] y)
    {
        y[0] = cast(ubyte)((x>>56)&255); y[1] = cast(ubyte)((x>>48)&255);
        y[2] = cast(ubyte)((x>>40)&255); y[3] = cast(ubyte)((x>>32)&255);
        y[4] = cast(ubyte)((x>>24)&255); y[5] = cast(ubyte)((x>>16)&255);
        y[6] = cast(ubyte)((x>>8 )&255); y[7] = cast(ubyte)( x     &255);
    }
    
    void LOAD64H(ref ulong x, ref ubyte[8] y)                                                      
    {
        x = ((cast(ulong)(y[0] & 255))<<56)|((cast(ulong)(y[1] & 255))<<48) | 
            ((cast(ulong)(y[2] & 255))<<40)|((cast(ulong)(y[3] & 255))<<32) | 
            ((cast(ulong)(y[4] & 255))<<24)|((cast(ulong)(y[5] & 255))<<16) | 
            ((cast(ulong)(y[6] & 255))<<8 )|((cast(ulong)(y[7] & 255)));
    } 

} /* ENDIAN_NEUTRAL */

version(ENDIAN_LITTLE)
{
    version(LTC_NO_BSWAP) {}
    else
    {
        void STORE32H(uint x, ref ubyte[4] y)
        {
            y[0] = cast(ubyte)((x>>24)&255); y[1] = cast(ubyte)((x>>16)&255);   
            y[2] = cast(ubyte)((x>>8 )&255); y[3] = cast(ubyte)( x     &255); 
        }
        
        void LOAD32H(ref uint x, ref ubyte[4] y)
        {
            x = (cast(uint)(y[0] & 255)<<24) |
                (cast(uint)(y[1] & 255)<<16) |
                (cast(uint)(y[2] & 255)<<8)  |
                (cast(uint)(y[3] & 255));
        }
    }


    /* x86_64 processor */
    version(LTC_NO_BSWAP) {}
    else
    {
        void STORE64H(ulong x, ref ubyte[8] y)
        {
            y[0] = cast(ubyte)((x>>56)&255); y[1] = cast(ubyte)((x>>48)&255);
            y[2] = cast(ubyte)((x>>40)&255); y[3] = cast(ubyte)((x>>32)&255);
            y[4] = cast(ubyte)((x>>24)&255); y[5] = cast(ubyte)((x>>16)&255);
            y[6] = cast(ubyte)((x>>8 )&255); y[7] = cast(ubyte)( x     &255);
        }
        
        void LOAD64H(x, y)                                                      
        {
            x = ((cast(ulong)(y[0] & 255))<<56)|((cast(ulong)(y[1] & 255))<<48) | 
                ((cast(ulong)(y[2] & 255))<<40)|((cast(ulong)(y[3] & 255))<<32) | 
                ((cast(ulong)(y[4] & 255))<<24)|((cast(ulong)(y[5] & 255))<<16) | 
                ((cast(ulong)(y[6] & 255))<<8 )|((cast(ulong)(y[7] & 255)));
        } 
    }

    version(ENDIAN_32BITWORD)
    {
        void STORE32L(uint x, ref ubyte[4] y)
        {
            y[] = (cast(ubyte*)&x)[0 .. 4];
        }
        
        void LOAD32L(ref uint x, ref ubyte[4] y)
        {
            (cast(ubyte*)&x)[0 .. 4] = y[]; 
        }
        
        void STORE64L(ulong x, ref ubyte[8] y)
        {
            y[7] = cast(ubyte)((x>>56)&255); y[6] = cast(ubyte)((x>>48)&255);   
            y[5] = cast(ubyte)((x>>40)&255); y[4] = cast(ubyte)((x>>32)&255);   
            y[3] = cast(ubyte)((x>>24)&255); y[2] = cast(ubyte)((x>>16)&255);   
            y[1] = cast(ubyte)((x>>8)&255);  y[0] = cast(ubyte)(x&255); 
        }
        
        void LOAD64L(ref ulong x, ref ubyte[8] y)
        {
            x = ((cast(ulong)(y[7] & 255))<<56)|((cast(ulong)(y[6] & 255))<<48)| 
                ((cast(ulong)(y[5] & 255))<<40)|((cast(ulong)(y[4] & 255))<<32)| 
                ((cast(ulong)(y[3] & 255))<<24)|((cast(ulong)(y[2] & 255))<<16)| 
                ((cast(ulong)(y[1] & 255))<<8 )|((cast(ulong)(y[0] & 255)));
        }
    } 
    else /* 64-bit words then  */
    {
        
        void STORE32L(uint x, ref ubyte[4] y)
        {
            y[] = (cast(ubyte*)&x)[0 .. 4];
        }
        
        void LOAD32L(ref uint x, ref ubyte[4] y)
        {
            (cast(ubyte*)&x)[0 .. 4] = y[]; 
        }
        
        void STORE64L(ulong x, ref ubyte[8] y)
        {
            y[] = (cast(ubyte*)&x)[0 .. 8];
        }
        
        void LOAD64L(ref ulong x, ref ubyte[8] y)
        {
            (cast(ubyte*)&x)[0 .. 8] = y[];
        }
    } /* ENDIAN_64BITWORD */
} /* ENDIAN_LITTLE */

version(ENDIAN_BIG)
{
    void STORE32L(uint x, ref ubyte[4] y)
    {
        y[3] = cast(ubyte)((x>>24)&255); y[2] = cast(ubyte)((x>>16)&255);   
        y[1] = cast(ubyte)((x>>8 )&255); y[0] = cast(ubyte)(x&255); 
    }
    
    void LOAD32L(ref uint x, ref ubyte[4] y)
    {
        x = (cast(uint)(y[3] & 255)<<24) | 
            (cast(uint)(y[2] & 255)<<16) | 
            (cast(uint)(y[1] & 255)<<8)  | 
            (cast(uint)(y[0] & 255)); 
    }
    
    void STORE64L(ulong x, ref ubyte[8] y)
    {
        y[7] = cast(ubyte)((x>>56)&255); y[6] = cast(ubyte)((x>>48)&255);     
        y[5] = cast(ubyte)((x>>40)&255); y[4] = cast(ubyte)((x>>32)&255);
        y[3] = cast(ubyte)((x>>24)&255); y[2] = cast(ubyte)((x>>16)&255);
        y[1] = cast(ubyte)((x>>8 )&255); y[0] = cast(ubyte)( x     &255); 
    }
    
    void LOAD64L(ref ulong x, ref ubyte[8] y)
    {
        x = ((cast(ulong)(y[7] & 255))<<56)|((cast(ulong)(y[6] & 255))<<48) |
            ((cast(ulong)(y[5] & 255))<<40)|((cast(ulong)(y[4] & 255))<<32) |
            ((cast(ulong)(y[3] & 255))<<24)|((cast(ulong)(y[2] & 255))<<16) |
            ((cast(ulong)(y[1] & 255))<<8)|((cast(ulong)(y[0] & 255))); 
    }
    
    version(ENDIAN_32BITWORD)
    { 
        void STORE32H(uint x, ref ubyte[4] y)
        {
            y[] = (cast(ubyte*)&x)[0 .. 4];
        }
        
        void LOAD32H(ref uint x, ref ubyte[4] y)
        {
            (cast(ubyte*)&x)[0 .. 4] = y[];
        }
        
        void STORE64H(ulong x, ref ubyte[8] y)
        {
            y[0] = cast(ubyte)((x>>56)&255); y[1] = cast(ubyte)((x>>48)&255);
            y[2] = cast(ubyte)((x>>40)&255); y[3] = cast(ubyte)((x>>32)&255);
            y[4] = cast(ubyte)((x>>24)&255); y[5] = cast(ubyte)((x>>16)&255);
            y[6] = cast(ubyte)((x>>8) &255); y[7] = cast(ubyte)( x     &255);
        }
        
        void LOAD64H(ref ulong x, ref ubyte[8] y)
        {
            x = ((cast(ulong)(y[0] & 255))<<56)|((cast(ulong)(y[1] & 255))<<48)|
                ((cast(ulong)(y[2] & 255))<<40)|((cast(ulong)(y[3] & 255))<<32)|
                ((cast(ulong)(y[4] & 255))<<24)|((cast(ulong)(y[5] & 255))<<16)|
                ((cast(ulong)(y[6] & 255))<<8) |((cast(ulong)(y[7] & 255)));
        }
    }
    else /* 64-bit words then  */
    {
        void STORE32H(uint x, ref ubyte[4] y)
        {
            y[] = (cast(ubyte*)&x)[0 .. 4];
        }
        
        void LOAD32H(ref uint x, ref ubyte[4] y)
        {
            (cast(ubyte*)&x)[0 .. 4] = y[];
        }
        
        void STORE64H(ulong x, ref ubyte[8] y)
        {
            y[] = (cast(ubyte*)&x)[0 .. 8];
        }
        
        void LOAD64H(ref ulong x, ref ubyte[8] y)
        {
            (cast(ubyte*)&x)[0 .. 8] = y[];
        }
    } /* ENDIAN_64BITWORD */
} /* ENDIAN_BIG */

void BSWAP(ref uint x)
{
    x = ((x>>24)&0x000000FFUL) | ((x<<24)&0xFF000000UL)  |
        ((x>>8 )&0x0000FF00UL) | ((x<<8 )&0x00FF0000UL);
}

/* 32-bit Rotates */
/* rotates the hard way */
uint ROL(uint x, int y) { return ((cast(uint)x<<cast(uint)(y&31)) | ((cast(uint)x&0xFFFFFFFFUL)>>cast(uint)(32-(y&31)))) & 0xFFFFFFFFUL;}
uint ROR(uint x, int y) { return (((cast(uint)x&0xFFFFFFFFUL)>>cast(uint)(y&31)) | (cast(uint)x<<cast(uint)(32-(y&31)))) & 0xFFFFFFFFUL;}
uint ROLc(uint x, const int y) { return ((cast(uint)x<<cast(uint)(y&31)) | ((cast(uint)x&0xFFFFFFFFUL)>>cast(uint)(32-(y&31)))) & 0xFFFFFFFFUL;}
uint RORc(uint x, const int y) { return (((cast(uint)x&0xFFFFFFFFUL)>>cast(uint)(y&31)) | (cast(uint)x<<cast(uint)(32-(y&31)))) & 0xFFFFFFFFUL;}


/* 64-bit Rotates */
ulong ROL64(ulong x, int y)
{
    return ((x<<(cast(ulong)y&63)) | 
           ((x&0xFFFFFFFFFFFFFFFFUL)>>(cast(ulong)64-(y&63)))) & 0xFFFFFFFFFFFFFFFFUL;
}

ulong ROR64(ulong x, int y)
{
    return (((x&0xFFFFFFFFFFFFFFFFUL)>>(cast(ulong)y&63UL)) | 
      (x<<(cast(ulong)(64-(y&63UL))))) & 0xFFFFFFFFFFFFFFFFUL;
}

ulong ROL64c(ulong x, const int y)
{
    return ((x<<(cast(ulong)y&63)) |
           ((x&0xFFFFFFFFFFFFFFFFUL)>>(cast(ulong)64-(y&63)))) & 0xFFFFFFFFFFFFFFFFUL;
}

ulong ROR64c(ulong x, const int y)
{
    return (((x&0xFFFFFFFFFFFFFFFFUL)>>(cast(ulong)y&63UL)) |
           (x<<(cast(ulong)(64-(y&63UL))))) & 0xFFFFFFFFFFFFFFFFUL;
}

T MAX(T)(T x, T y) { return x > y ? x : y; }
T MIN(T)(T x, T y) { return x < y ? x : y; }


/* extract a byte portably */
ubyte _byte(T)(T x, uint n) { return (x >> (8 * n)) & 255; }


/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_macros.h,v $ */
/* $Revision: 1.15 $ */
/* $Date: 2006/11/29 23:43:57 $ */