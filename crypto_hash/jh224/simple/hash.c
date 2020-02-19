#include "crypto_hash.h"
#include "crypto_uint64.h"
#include <string.h>

typedef crypto_uint64 uint64;

const unsigned char iv[128] =
{0x82,0xc2,0x70,0xe0,0xb,0xed,0x2,0x30,0x8d,0xc,0x3a,0x9e,0x31,0xce,0x34,0xb1,0x8f,0xc,0x94,0x2f,0xba,0x46,0xcd,0x87,0x1e,0xc4,0xd8,0xa,0xfc,0x79,0x71,0xc4,0x61,0xe0,0x1a,0xbb,0x69,0x96,0x2d,0x7b,0xaf,0x71,0x89,0x3d,0xe1,0x3d,0x86,0x97,0xd2,0x52,0x4,0x60,0xf7,0xc9,0xc0,0x94,0xc7,0x63,0x49,0xca,0x3d,0xa5,0x79,0x9c,0xfd,0x8b,0x55,0x1f,0xbd,0xbc,0xeb,0x9f,0x8,0x34,0xbd,0x5b,0xb4,0x42,0xf8,0xbf,0xba,0x51,0x5c,0x35,0xb9,0xc7,0x99,0x9e,0x55,0xa4,0x4e,0x62,0x71,0xcc,0x13,0xb3,0x85,0x72,0x57,0x93,0xc1,0x85,0xf7,0x25,0x45,0x36,0x6b,0x69,0x0,0x50,0x25,0xd2,0x33,0x90,0xeb,0xdb,0x27,0xdd,0x1e,0xdf,0xcc,0xba,0xad,0xe1,0x7e,0x60,0x3d,0xe9};

const unsigned char c[36][32]={
{0x72,0xd5,0xde,0xa2,0xdf,0x15,0xf8,0x67,0x7b,0x84,0x15,0xa,0xb7,0x23,0x15,0x57,0x81,0xab,0xd6,0x90,0x4d,0x5a,0x87,0xf6,0x4e,0x9f,0x4f,0xc5,0xc3,0xd1,0x2b,0x40},
{0xea,0x98,0x3a,0xe0,0x5c,0x45,0xfa,0x9c,0x3,0xc5,0xd2,0x99,0x66,0xb2,0x99,0x9a,0x66,0x2,0x96,0xb4,0xf2,0xbb,0x53,0x8a,0xb5,0x56,0x14,0x1a,0x88,0xdb,0xa2,0x31},
{0x3,0xa3,0x5a,0x5c,0x9a,0x19,0xe,0xdb,0x40,0x3f,0xb2,0xa,0x87,0xc1,0x44,0x10,0x1c,0x5,0x19,0x80,0x84,0x9e,0x95,0x1d,0x6f,0x33,0xeb,0xad,0x5e,0xe7,0xcd,0xdc},
{0x10,0xba,0x13,0x92,0x2,0xbf,0x6b,0x41,0xdc,0x78,0x65,0x15,0xf7,0xbb,0x27,0xd0,0xa,0x2c,0x81,0x39,0x37,0xaa,0x78,0x50,0x3f,0x1a,0xbf,0xd2,0x41,0x0,0x91,0xd3},
{0x42,0x2d,0x5a,0xd,0xf6,0xcc,0x7e,0x90,0xdd,0x62,0x9f,0x9c,0x92,0xc0,0x97,0xce,0x18,0x5c,0xa7,0xb,0xc7,0x2b,0x44,0xac,0xd1,0xdf,0x65,0xd6,0x63,0xc6,0xfc,0x23},
{0x97,0x6e,0x6c,0x3,0x9e,0xe0,0xb8,0x1a,0x21,0x5,0x45,0x7e,0x44,0x6c,0xec,0xa8,0xee,0xf1,0x3,0xbb,0x5d,0x8e,0x61,0xfa,0xfd,0x96,0x97,0xb2,0x94,0x83,0x81,0x97},
{0x4a,0x8e,0x85,0x37,0xdb,0x3,0x30,0x2f,0x2a,0x67,0x8d,0x2d,0xfb,0x9f,0x6a,0x95,0x8a,0xfe,0x73,0x81,0xf8,0xb8,0x69,0x6c,0x8a,0xc7,0x72,0x46,0xc0,0x7f,0x42,0x14},
{0xc5,0xf4,0x15,0x8f,0xbd,0xc7,0x5e,0xc4,0x75,0x44,0x6f,0xa7,0x8f,0x11,0xbb,0x80,0x52,0xde,0x75,0xb7,0xae,0xe4,0x88,0xbc,0x82,0xb8,0x0,0x1e,0x98,0xa6,0xa3,0xf4},
{0x8e,0xf4,0x8f,0x33,0xa9,0xa3,0x63,0x15,0xaa,0x5f,0x56,0x24,0xd5,0xb7,0xf9,0x89,0xb6,0xf1,0xed,0x20,0x7c,0x5a,0xe0,0xfd,0x36,0xca,0xe9,0x5a,0x6,0x42,0x2c,0x36},
{0xce,0x29,0x35,0x43,0x4e,0xfe,0x98,0x3d,0x53,0x3a,0xf9,0x74,0x73,0x9a,0x4b,0xa7,0xd0,0xf5,0x1f,0x59,0x6f,0x4e,0x81,0x86,0xe,0x9d,0xad,0x81,0xaf,0xd8,0x5a,0x9f},
{0xa7,0x5,0x6,0x67,0xee,0x34,0x62,0x6a,0x8b,0xb,0x28,0xbe,0x6e,0xb9,0x17,0x27,0x47,0x74,0x7,0x26,0xc6,0x80,0x10,0x3f,0xe0,0xa0,0x7e,0x6f,0xc6,0x7e,0x48,0x7b},
{0xd,0x55,0xa,0xa5,0x4a,0xf8,0xa4,0xc0,0x91,0xe3,0xe7,0x9f,0x97,0x8e,0xf1,0x9e,0x86,0x76,0x72,0x81,0x50,0x60,0x8d,0xd4,0x7e,0x9e,0x5a,0x41,0xf3,0xe5,0xb0,0x62},
{0xfc,0x9f,0x1f,0xec,0x40,0x54,0x20,0x7a,0xe3,0xe4,0x1a,0x0,0xce,0xf4,0xc9,0x84,0x4f,0xd7,0x94,0xf5,0x9d,0xfa,0x95,0xd8,0x55,0x2e,0x7e,0x11,0x24,0xc3,0x54,0xa5},
{0x5b,0xdf,0x72,0x28,0xbd,0xfe,0x6e,0x28,0x78,0xf5,0x7f,0xe2,0xf,0xa5,0xc4,0xb2,0x5,0x89,0x7c,0xef,0xee,0x49,0xd3,0x2e,0x44,0x7e,0x93,0x85,0xeb,0x28,0x59,0x7f},
{0x70,0x5f,0x69,0x37,0xb3,0x24,0x31,0x4a,0x5e,0x86,0x28,0xf1,0x1d,0xd6,0xe4,0x65,0xc7,0x1b,0x77,0x4,0x51,0xb9,0x20,0xe7,0x74,0xfe,0x43,0xe8,0x23,0xd4,0x87,0x8a},
{0x7d,0x29,0xe8,0xa3,0x92,0x76,0x94,0xf2,0xdd,0xcb,0x7a,0x9,0x9b,0x30,0xd9,0xc1,0x1d,0x1b,0x30,0xfb,0x5b,0xdc,0x1b,0xe0,0xda,0x24,0x49,0x4f,0xf2,0x9c,0x82,0xbf},
{0xa4,0xe7,0xba,0x31,0xb4,0x70,0xbf,0xff,0xd,0x32,0x44,0x5,0xde,0xf8,0xbc,0x48,0x3b,0xae,0xfc,0x32,0x53,0xbb,0xd3,0x39,0x45,0x9f,0xc3,0xc1,0xe0,0x29,0x8b,0xa0},
{0xe5,0xc9,0x5,0xfd,0xf7,0xae,0x9,0xf,0x94,0x70,0x34,0x12,0x42,0x90,0xf1,0x34,0xa2,0x71,0xb7,0x1,0xe3,0x44,0xed,0x95,0xe9,0x3b,0x8e,0x36,0x4f,0x2f,0x98,0x4a},
{0x88,0x40,0x1d,0x63,0xa0,0x6c,0xf6,0x15,0x47,0xc1,0x44,0x4b,0x87,0x52,0xaf,0xff,0x7e,0xbb,0x4a,0xf1,0xe2,0xa,0xc6,0x30,0x46,0x70,0xb6,0xc5,0xcc,0x6e,0x8c,0xe6},
{0xa4,0xd5,0xa4,0x56,0xbd,0x4f,0xca,0x0,0xda,0x9d,0x84,0x4b,0xc8,0x3e,0x18,0xae,0x73,0x57,0xce,0x45,0x30,0x64,0xd1,0xad,0xe8,0xa6,0xce,0x68,0x14,0x5c,0x25,0x67},
{0xa3,0xda,0x8c,0xf2,0xcb,0xe,0xe1,0x16,0x33,0xe9,0x6,0x58,0x9a,0x94,0x99,0x9a,0x1f,0x60,0xb2,0x20,0xc2,0x6f,0x84,0x7b,0xd1,0xce,0xac,0x7f,0xa0,0xd1,0x85,0x18},
{0x32,0x59,0x5b,0xa1,0x8d,0xdd,0x19,0xd3,0x50,0x9a,0x1c,0xc0,0xaa,0xa5,0xb4,0x46,0x9f,0x3d,0x63,0x67,0xe4,0x4,0x6b,0xba,0xf6,0xca,0x19,0xab,0xb,0x56,0xee,0x7e},
{0x1f,0xb1,0x79,0xea,0xa9,0x28,0x21,0x74,0xe9,0xbd,0xf7,0x35,0x3b,0x36,0x51,0xee,0x1d,0x57,0xac,0x5a,0x75,0x50,0xd3,0x76,0x3a,0x46,0xc2,0xfe,0xa3,0x7d,0x70,0x1},
{0xf7,0x35,0xc1,0xaf,0x98,0xa4,0xd8,0x42,0x78,0xed,0xec,0x20,0x9e,0x6b,0x67,0x79,0x41,0x83,0x63,0x15,0xea,0x3a,0xdb,0xa8,0xfa,0xc3,0x3b,0x4d,0x32,0x83,0x2c,0x83},
{0xa7,0x40,0x3b,0x1f,0x1c,0x27,0x47,0xf3,0x59,0x40,0xf0,0x34,0xb7,0x2d,0x76,0x9a,0xe7,0x3e,0x4e,0x6c,0xd2,0x21,0x4f,0xfd,0xb8,0xfd,0x8d,0x39,0xdc,0x57,0x59,0xef},
{0x8d,0x9b,0xc,0x49,0x2b,0x49,0xeb,0xda,0x5b,0xa2,0xd7,0x49,0x68,0xf3,0x70,0xd,0x7d,0x3b,0xae,0xd0,0x7a,0x8d,0x55,0x84,0xf5,0xa5,0xe9,0xf0,0xe4,0xf8,0x8e,0x65},
{0xa0,0xb8,0xa2,0xf4,0x36,0x10,0x3b,0x53,0xc,0xa8,0x7,0x9e,0x75,0x3e,0xec,0x5a,0x91,0x68,0x94,0x92,0x56,0xe8,0x88,0x4f,0x5b,0xb0,0x5c,0x55,0xf8,0xba,0xbc,0x4c},
{0xe3,0xbb,0x3b,0x99,0xf3,0x87,0x94,0x7b,0x75,0xda,0xf4,0xd6,0x72,0x6b,0x1c,0x5d,0x64,0xae,0xac,0x28,0xdc,0x34,0xb3,0x6d,0x6c,0x34,0xa5,0x50,0xb8,0x28,0xdb,0x71},
{0xf8,0x61,0xe2,0xf2,0x10,0x8d,0x51,0x2a,0xe3,0xdb,0x64,0x33,0x59,0xdd,0x75,0xfc,0x1c,0xac,0xbc,0xf1,0x43,0xce,0x3f,0xa2,0x67,0xbb,0xd1,0x3c,0x2,0xe8,0x43,0xb0},
{0x33,0xa,0x5b,0xca,0x88,0x29,0xa1,0x75,0x7f,0x34,0x19,0x4d,0xb4,0x16,0x53,0x5c,0x92,0x3b,0x94,0xc3,0xe,0x79,0x4d,0x1e,0x79,0x74,0x75,0xd7,0xb6,0xee,0xaf,0x3f},
{0xea,0xa8,0xd4,0xf7,0xbe,0x1a,0x39,0x21,0x5c,0xf4,0x7e,0x9,0x4c,0x23,0x27,0x51,0x26,0xa3,0x24,0x53,0xba,0x32,0x3c,0xd2,0x44,0xa3,0x17,0x4a,0x6d,0xa6,0xd5,0xad},
{0xb5,0x1d,0x3e,0xa6,0xaf,0xf2,0xc9,0x8,0x83,0x59,0x3d,0x98,0x91,0x6b,0x3c,0x56,0x4c,0xf8,0x7c,0xa1,0x72,0x86,0x60,0x4d,0x46,0xe2,0x3e,0xcc,0x8,0x6e,0xc7,0xf6},
{0x2f,0x98,0x33,0xb3,0xb1,0xbc,0x76,0x5e,0x2b,0xd6,0x66,0xa5,0xef,0xc4,0xe6,0x2a,0x6,0xf4,0xb6,0xe8,0xbe,0xc1,0xd4,0x36,0x74,0xee,0x82,0x15,0xbc,0xef,0x21,0x63},
{0xfd,0xc1,0x4e,0xd,0xf4,0x53,0xc9,0x69,0xa7,0x7d,0x5a,0xc4,0x6,0x58,0x58,0x26,0x7e,0xc1,0x14,0x16,0x6,0xe0,0xfa,0x16,0x7e,0x90,0xaf,0x3d,0x28,0x63,0x9d,0x3f},
{0xd2,0xc9,0xf2,0xe3,0x0,0x9b,0xd2,0xc,0x5f,0xaa,0xce,0x30,0xb7,0xd4,0xc,0x30,0x74,0x2a,0x51,0x16,0xf2,0xe0,0x32,0x98,0xd,0xeb,0x30,0xd8,0xe3,0xce,0xf8,0x9a},
{0x4b,0xc5,0x9e,0x7b,0xb5,0xf1,0x79,0x92,0xff,0x51,0xe6,0x6e,0x4,0x86,0x68,0xd3,0x9b,0x23,0x4d,0x57,0xe6,0x96,0x67,0x31,0xcc,0xe6,0xa6,0xf3,0x17,0xa,0x75,0x5}};

#define SWAP1(x)   (x) = (((x & 0x5555555555555555ULL) << 1) | ((x >> 1) & 0x5555555555555555ULL));
#define SWAP2(x)   (x) = (((x & 0x3333333333333333ULL) << 2) | (((x >> 2) & 0x3333333333333333ULL)));
#define SWAP4(x)   (x) = (((x & 0x0f0f0f0f0f0f0f0fULL) << 4) | (((x >> 4) & 0x0f0f0f0f0f0f0f0fULL))); 
#define SWAP8(x)   (x) = (((x & 0x00ff00ff00ff00ffULL) << 8) | (((x >> 8) & 0x00ff00ff00ff00ffULL))); 
#define SWAP16(x)  (x) = (((x & 0x0000ffff0000ffffULL) << 16) | (((x >> 16) & 0x0000ffff0000ffffULL)));
#define SWAP32(x)  (x) = (((x) << 32) | ((x) >> 32));

#define L(m0,m1,m2,m3,m4,m5,m6,m7) \
    (m4) ^= (m1);        \
    (m5) ^= (m2);        \
    (m6) ^= (m0) ^ (m3);     \
    (m7) ^= (m0);        \
    (m0) ^= (m5);        \
    (m1) ^= (m6);        \
    (m2) ^= (m4) ^ (m7);     \
    (m3) ^= (m4); 

#define SS(m0,m1,m2,m3,m4,m5,m6,m7,cc0,cc1)   \
    m0 ^= (~m2 & cc0);    \
    m4 ^= (~m6 & cc1);    \
    temp0 = cc0 ^ (m0 & m1);\
    temp1 = cc1 ^ (m4 & m5);\
    m0 ^= (m2 & ~m3);      \
    m4 ^= (m6 & ~m7);      \
    m3 ^= (m1 | ~m2);     \
    m7 ^= (m5 | ~m6);     \
    m1 ^= (m0 & m2);      \
    m5 ^= (m4 & m6);      \
    m2 ^= (m0 & ~m3);     \
    m6 ^= (m4 & ~m7);     \
    m0 ^= (m1 | m3);      \
    m4 ^= (m5 | m7);      \
    m3 ^= (m1 & m2);      \
    m7 ^= (m5 & m6);      \
    m1 ^= (temp0 & m0);     \
    m5 ^= (temp1 & m4);     \
    m2 ^= temp0;          \
    m6 ^= temp1; 

void F8(uint64 (*x)[2],const unsigned char *buf) 
{
  uint64 x00 = x[0][0];
  uint64 x01 = x[0][1];
  uint64 x10 = x[1][0];
  uint64 x11 = x[1][1];
  uint64 x20 = x[2][0];
  uint64 x21 = x[2][1];
  uint64 x30 = x[3][0];
  uint64 x31 = x[3][1];
  uint64 x40 = x[4][0];
  uint64 x41 = x[4][1];
  uint64 x50 = x[5][0];
  uint64 x51 = x[5][1];
  uint64 x60 = x[6][0];
  uint64 x61 = x[6][1];
  uint64 x70 = x[7][0];
  uint64 x71 = x[7][1];
  int r;
  uint64 temp0;
  uint64 temp1;

  x00 ^= ((uint64 *) buf)[0];
  x01 ^= ((uint64 *) buf)[1];
  x10 ^= ((uint64 *) buf)[2];
  x11 ^= ((uint64 *) buf)[3];
  x20 ^= ((uint64 *) buf)[4];
  x21 ^= ((uint64 *) buf)[5];
  x30 ^= ((uint64 *) buf)[6];
  x31 ^= ((uint64 *) buf)[7];

  for (r = 0; r < 35; r = r+7) {
    SS(x00,x20,x40,x60,x10,x30,x50,x70,((uint64*)c[r+0])[0],((uint64*)c[r+0])[0+2] );          
    L(x00,x20,x40,x60,x10,x30,x50,x70);
    SWAP1(x10); SWAP1(x30); SWAP1(x50); SWAP1(x70);
    SS(x00,x20,x40,x60,x10,x30,x50,x70,((uint64*)c[r+1])[0],((uint64*)c[r+1])[0+2] );          
    L(x00,x20,x40,x60,x10,x30,x50,x70);
    SWAP2(x10); SWAP2(x30); SWAP2(x50); SWAP2(x70);       
    SS(x00,x20,x40,x60,x10,x30,x50,x70,((uint64*)c[r+2])[0],((uint64*)c[r+2])[0+2] );          
    L(x00,x20,x40,x60,x10,x30,x50,x70);
    SWAP4(x10); SWAP4(x30); SWAP4(x50); SWAP4(x70);
    SS(x00,x20,x40,x60,x10,x30,x50,x70,((uint64*)c[r+3])[0],((uint64*)c[r+3])[0+2] );          
    L(x00,x20,x40,x60,x10,x30,x50,x70);
    SWAP8(x10); SWAP8(x30); SWAP8(x50); SWAP8(x70);
    SS(x00,x20,x40,x60,x10,x30,x50,x70,((uint64*)c[r+4])[0],((uint64*)c[r+4])[0+2] );          
    L(x00,x20,x40,x60,x10,x30,x50,x70);
    SWAP16(x10); SWAP16(x30); SWAP16(x50); SWAP16(x70);      
    SS(x00,x20,x40,x60,x10,x30,x50,x70,((uint64*)c[r+5])[0],((uint64*)c[r+5])[0+2] );          
    L(x00,x20,x40,x60,x10,x30,x50,x70);
    SWAP32(x10); SWAP32(x30); SWAP32(x50); SWAP32(x70); 
    SS(x00,x20,x40,x60,x10,x30,x50,x70,((uint64*)c[r+6])[0],((uint64*)c[r+6])[0+2] );          
    L(x00,x20,x40,x60,x10,x30,x50,x70);

      SS(x01,x21,x41,x61,x11,x31,x51,x71,((uint64*)c[r+0])[1],((uint64*)c[r+0])[1+2] );          
      L(x01,x21,x41,x61,x11,x31,x51,x71);
      SWAP1(x11); SWAP1(x31); SWAP1(x51); SWAP1(x71);
      SS(x01,x21,x41,x61,x11,x31,x51,x71,((uint64*)c[r+1])[1],((uint64*)c[r+1])[1+2] );          
      L(x01,x21,x41,x61,x11,x31,x51,x71);
      SWAP2(x11); SWAP2(x31); SWAP2(x51); SWAP2(x71);       
      SS(x01,x21,x41,x61,x11,x31,x51,x71,((uint64*)c[r+2])[1],((uint64*)c[r+2])[1+2] );          
      L(x01,x21,x41,x61,x11,x31,x51,x71);
      SWAP4(x11); SWAP4(x31); SWAP4(x51); SWAP4(x71);
      SS(x01,x21,x41,x61,x11,x31,x51,x71,((uint64*)c[r+3])[1],((uint64*)c[r+3])[1+2] );          
      L(x01,x21,x41,x61,x11,x31,x51,x71);
      SWAP8(x11); SWAP8(x31); SWAP8(x51); SWAP8(x71);
      SS(x01,x21,x41,x61,x11,x31,x51,x71,((uint64*)c[r+4])[1],((uint64*)c[r+4])[1+2] );          
      L(x01,x21,x41,x61,x11,x31,x51,x71);
      SWAP16(x11); SWAP16(x31); SWAP16(x51); SWAP16(x71);      
      SS(x01,x21,x41,x61,x11,x31,x51,x71,((uint64*)c[r+5])[1],((uint64*)c[r+5])[1+2] );          
      L(x01,x21,x41,x61,x11,x31,x51,x71);
      SWAP32(x11); SWAP32(x31); SWAP32(x51); SWAP32(x71); 
      SS(x01,x21,x41,x61,x11,x31,x51,x71,((uint64*)c[r+6])[1],((uint64*)c[r+6])[1+2] );          
      L(x01,x21,x41,x61,x11,x31,x51,x71);

    temp0 = x10; x10 = x11; x11 = temp0; 
    temp0 = x30; x30 = x31; x31 = temp0; 
    temp0 = x50; x50 = x51; x51 = temp0; 
    temp0 = x70; x70 = x71; x71 = temp0; 
  }

  SS(x00,x20,x40,x60,x10,x30,x50,x70,((uint64*)c[35])[0],((uint64*)c[35])[0+2] );          
  SS(x01,x21,x41,x61,x11,x31,x51,x71,((uint64*)c[35])[1],((uint64*)c[35])[1+2] );          

  x40 ^= ((uint64 *) buf)[0];
  x41 ^= ((uint64 *) buf)[1];
  x50 ^= ((uint64 *) buf)[2];
  x51 ^= ((uint64 *) buf)[3];
  x60 ^= ((uint64 *) buf)[4];
  x61 ^= ((uint64 *) buf)[5];
  x70 ^= ((uint64 *) buf)[6];
  x71 ^= ((uint64 *) buf)[7];

  x[0][0] = x00;
  x[0][1] = x01;
  x[1][0] = x10;
  x[1][1] = x11;
  x[2][0] = x20;
  x[2][1] = x21;
  x[3][0] = x30;
  x[3][1] = x31;
  x[4][0] = x40;
  x[4][1] = x41;
  x[5][0] = x50;
  x[5][1] = x51;
  x[6][0] = x60;
  x[6][1] = x61;
  x[7][0] = x70;
  x[7][1] = x71;
}

int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  uint64 x[8][2];
  unsigned char buffer[64];
  unsigned long long bits = inlen * 8;
  int i;

  memcpy(x,iv,128);

  while (inlen >= 64) {
    F8(x,in);
    in += 64;
    inlen -= 64;
  }

  if (inlen > 0) {
    memset(buffer, 0, 64);
    memcpy(buffer, in, inlen);
    buffer[inlen] |= 128;
    F8(x,buffer);
    memset(buffer, 0, 64);
  } else {
    memset(buffer, 0, 64);
    buffer[0] = 128;
  }

  buffer[63] = bits & 0xff;
  buffer[62] = (bits >> 8) & 0xff;
  buffer[61] = (bits >> 16) & 0xff;
  buffer[60] = (bits >> 24) & 0xff;
  buffer[59] = (bits >> 32) & 0xff;
  buffer[58] = (bits >> 40) & 0xff;
  buffer[57] = (bits >> 48) & 0xff;
  buffer[56] = (bits >> 56) & 0xff;
  F8(x,buffer);

  memcpy(out,(unsigned char*)x+64+36,28);

  return 0;
}
