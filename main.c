/*********************************************************************
* Filename:   aes_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding AES
              implementation. These tests do not encompass the full
              range of available test vectors and are not sufficient
              for FIPS-140 certification. However, if the tests pass
              it is very, very likely that the code is correct and was
              compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
//#include "aes.h"



/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define AES_BLOCK_SIZE 16               // AES operates on 16 bytes at a time
#define BLOWFISH_BLOCK_SIZE 8 // Blowfish operates on 8 bytes at a time
#define DES_BLOCK_SIZE 8 //same like blowfish
/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;            // 8-bit byte
typedef unsigned int WORD; // 32-bit word, change to "long" for 16-bit machines

typedef struct {
   WORD p[18];
   WORD s[4][256];
} BLOWFISH_KEY;

typedef enum {
	DES_ENCRYPT,
	DES_DECRYPT
} DES_MODE;


/********************/
/*********************************************************************
* Filename:   aes.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    This code is the implementation of the AES algorithm and
              the CTR, CBC, and CCM modes of operation it can be used in.
               AES is, specified by the NIST in in publication FIPS PUB 197,
              availible at:
               * http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf .
              The CBC and CTR modes of operation are specified by
              NIST SP 800-38 A, available at:
               * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf .
              The CCM mode of operation is specified by NIST SP80-38 C, available at:
               * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>


#include <stdio.h>

/****************************** MACROS ******************************/
// The least significant byte of the word is rotated to the end.
#define KE_ROTWORD(x) (((x) << 8) | ((x) >> 24))

#define TRUE  1
#define FALSE 0

/**************************** DATA TYPES ****************************/
#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14

/*********************** FUNCTION DECLARATIONS **********************/
void ccm_prepare_first_ctr_blk(BYTE counter[], const BYTE nonce[], int nonce_len, int payload_len_store_size);
void ccm_prepare_first_format_blk(BYTE buf[], int assoc_len, int payload_len, int payload_len_store_size, int mac_len, const BYTE nonce[], int nonce_len);
void ccm_format_assoc_data(BYTE buf[], int *end_of_buf, const BYTE assoc[], int assoc_len);
void ccm_format_payload_data(BYTE buf[], int *end_of_buf, const BYTE payload[], int payload_len);


/*********** CHAHAPOLY/

/***********CHAHA POLY/



/**************************** VARIABLES *****************************/
// This is the specified AES SBox. To look up a substitution value, put the first
// nibble in the first index (row) and the second nibble in the second index (column).


#define F(x,t) t = keystruct->s[0][(x) >> 24]; \
               t += keystruct->s[1][((x) >> 16) & 0xff]; \
               t ^= keystruct->s[2][((x) >> 8) & 0xff]; \
               t += keystruct->s[3][(x) & 0xff];
#define swap(r,l,t) t = l; l = r; r = t;
#define ITERATION(l,r,t,pval) l ^= keystruct->p[pval]; F(l,t); r^= t; swap(r,l,t);


static const BYTE aes_sbox[16][16] = {
	{0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76},
	{0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0},
	{0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15},
	{0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75},
	{0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84},
	{0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF},
	{0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8},
	{0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2},
	{0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73},
	{0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB},
	{0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79},
	{0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08},
	{0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A},
	{0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E},
	{0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF},
	{0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16}
};

static const BYTE aes_invsbox[16][16] = {
	{0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB},
	{0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB},
	{0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E},
	{0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25},
	{0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92},
	{0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84},
	{0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06},
	{0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B},
	{0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73},
	{0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E},
	{0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B},
	{0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4},
	{0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F},
	{0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF},
	{0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61},
	{0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D}
};

// This table stores pre-calculated values for all possible GF(2^8) calculations.This
// table is only used by the (Inv)MixColumns steps.
// USAGE: The second index (column) is the coefficient of multiplication. Only 7 different
// coefficients are used: 0x01, 0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e, but multiplication by
// 1 is negligible leaving only 6 coefficients. Each column of the table is devoted to one
// of these coefficients, in the ascending order of value, from values 0x00 to 0xFF.
static const BYTE gf_mul[256][6] = {
	{0x00,0x00,0x00,0x00,0x00,0x00},{0x02,0x03,0x09,0x0b,0x0d,0x0e},
	{0x04,0x06,0x12,0x16,0x1a,0x1c},{0x06,0x05,0x1b,0x1d,0x17,0x12},
	{0x08,0x0c,0x24,0x2c,0x34,0x38},{0x0a,0x0f,0x2d,0x27,0x39,0x36},
	{0x0c,0x0a,0x36,0x3a,0x2e,0x24},{0x0e,0x09,0x3f,0x31,0x23,0x2a},
	{0x10,0x18,0x48,0x58,0x68,0x70},{0x12,0x1b,0x41,0x53,0x65,0x7e},
	{0x14,0x1e,0x5a,0x4e,0x72,0x6c},{0x16,0x1d,0x53,0x45,0x7f,0x62},
	{0x18,0x14,0x6c,0x74,0x5c,0x48},{0x1a,0x17,0x65,0x7f,0x51,0x46},
	{0x1c,0x12,0x7e,0x62,0x46,0x54},{0x1e,0x11,0x77,0x69,0x4b,0x5a},
	{0x20,0x30,0x90,0xb0,0xd0,0xe0},{0x22,0x33,0x99,0xbb,0xdd,0xee},
	{0x24,0x36,0x82,0xa6,0xca,0xfc},{0x26,0x35,0x8b,0xad,0xc7,0xf2},
	{0x28,0x3c,0xb4,0x9c,0xe4,0xd8},{0x2a,0x3f,0xbd,0x97,0xe9,0xd6},
	{0x2c,0x3a,0xa6,0x8a,0xfe,0xc4},{0x2e,0x39,0xaf,0x81,0xf3,0xca},
	{0x30,0x28,0xd8,0xe8,0xb8,0x90},{0x32,0x2b,0xd1,0xe3,0xb5,0x9e},
	{0x34,0x2e,0xca,0xfe,0xa2,0x8c},{0x36,0x2d,0xc3,0xf5,0xaf,0x82},
	{0x38,0x24,0xfc,0xc4,0x8c,0xa8},{0x3a,0x27,0xf5,0xcf,0x81,0xa6},
	{0x3c,0x22,0xee,0xd2,0x96,0xb4},{0x3e,0x21,0xe7,0xd9,0x9b,0xba},
	{0x40,0x60,0x3b,0x7b,0xbb,0xdb},{0x42,0x63,0x32,0x70,0xb6,0xd5},
	{0x44,0x66,0x29,0x6d,0xa1,0xc7},{0x46,0x65,0x20,0x66,0xac,0xc9},
	{0x48,0x6c,0x1f,0x57,0x8f,0xe3},{0x4a,0x6f,0x16,0x5c,0x82,0xed},
	{0x4c,0x6a,0x0d,0x41,0x95,0xff},{0x4e,0x69,0x04,0x4a,0x98,0xf1},
	{0x50,0x78,0x73,0x23,0xd3,0xab},{0x52,0x7b,0x7a,0x28,0xde,0xa5},
	{0x54,0x7e,0x61,0x35,0xc9,0xb7},{0x56,0x7d,0x68,0x3e,0xc4,0xb9},
	{0x58,0x74,0x57,0x0f,0xe7,0x93},{0x5a,0x77,0x5e,0x04,0xea,0x9d},
	{0x5c,0x72,0x45,0x19,0xfd,0x8f},{0x5e,0x71,0x4c,0x12,0xf0,0x81},
	{0x60,0x50,0xab,0xcb,0x6b,0x3b},{0x62,0x53,0xa2,0xc0,0x66,0x35},
	{0x64,0x56,0xb9,0xdd,0x71,0x27},{0x66,0x55,0xb0,0xd6,0x7c,0x29},
	{0x68,0x5c,0x8f,0xe7,0x5f,0x03},{0x6a,0x5f,0x86,0xec,0x52,0x0d},
	{0x6c,0x5a,0x9d,0xf1,0x45,0x1f},{0x6e,0x59,0x94,0xfa,0x48,0x11},
	{0x70,0x48,0xe3,0x93,0x03,0x4b},{0x72,0x4b,0xea,0x98,0x0e,0x45},
	{0x74,0x4e,0xf1,0x85,0x19,0x57},{0x76,0x4d,0xf8,0x8e,0x14,0x59},
	{0x78,0x44,0xc7,0xbf,0x37,0x73},{0x7a,0x47,0xce,0xb4,0x3a,0x7d},
	{0x7c,0x42,0xd5,0xa9,0x2d,0x6f},{0x7e,0x41,0xdc,0xa2,0x20,0x61},
	{0x80,0xc0,0x76,0xf6,0x6d,0xad},{0x82,0xc3,0x7f,0xfd,0x60,0xa3},
	{0x84,0xc6,0x64,0xe0,0x77,0xb1},{0x86,0xc5,0x6d,0xeb,0x7a,0xbf},
	{0x88,0xcc,0x52,0xda,0x59,0x95},{0x8a,0xcf,0x5b,0xd1,0x54,0x9b},
	{0x8c,0xca,0x40,0xcc,0x43,0x89},{0x8e,0xc9,0x49,0xc7,0x4e,0x87},
	{0x90,0xd8,0x3e,0xae,0x05,0xdd},{0x92,0xdb,0x37,0xa5,0x08,0xd3},
	{0x94,0xde,0x2c,0xb8,0x1f,0xc1},{0x96,0xdd,0x25,0xb3,0x12,0xcf},
	{0x98,0xd4,0x1a,0x82,0x31,0xe5},{0x9a,0xd7,0x13,0x89,0x3c,0xeb},
	{0x9c,0xd2,0x08,0x94,0x2b,0xf9},{0x9e,0xd1,0x01,0x9f,0x26,0xf7},
	{0xa0,0xf0,0xe6,0x46,0xbd,0x4d},{0xa2,0xf3,0xef,0x4d,0xb0,0x43},
	{0xa4,0xf6,0xf4,0x50,0xa7,0x51},{0xa6,0xf5,0xfd,0x5b,0xaa,0x5f},
	{0xa8,0xfc,0xc2,0x6a,0x89,0x75},{0xaa,0xff,0xcb,0x61,0x84,0x7b},
	{0xac,0xfa,0xd0,0x7c,0x93,0x69},{0xae,0xf9,0xd9,0x77,0x9e,0x67},
	{0xb0,0xe8,0xae,0x1e,0xd5,0x3d},{0xb2,0xeb,0xa7,0x15,0xd8,0x33},
	{0xb4,0xee,0xbc,0x08,0xcf,0x21},{0xb6,0xed,0xb5,0x03,0xc2,0x2f},
	{0xb8,0xe4,0x8a,0x32,0xe1,0x05},{0xba,0xe7,0x83,0x39,0xec,0x0b},
	{0xbc,0xe2,0x98,0x24,0xfb,0x19},{0xbe,0xe1,0x91,0x2f,0xf6,0x17},
	{0xc0,0xa0,0x4d,0x8d,0xd6,0x76},{0xc2,0xa3,0x44,0x86,0xdb,0x78},
	{0xc4,0xa6,0x5f,0x9b,0xcc,0x6a},{0xc6,0xa5,0x56,0x90,0xc1,0x64},
	{0xc8,0xac,0x69,0xa1,0xe2,0x4e},{0xca,0xaf,0x60,0xaa,0xef,0x40},
	{0xcc,0xaa,0x7b,0xb7,0xf8,0x52},{0xce,0xa9,0x72,0xbc,0xf5,0x5c},
	{0xd0,0xb8,0x05,0xd5,0xbe,0x06},{0xd2,0xbb,0x0c,0xde,0xb3,0x08},
	{0xd4,0xbe,0x17,0xc3,0xa4,0x1a},{0xd6,0xbd,0x1e,0xc8,0xa9,0x14},
	{0xd8,0xb4,0x21,0xf9,0x8a,0x3e},{0xda,0xb7,0x28,0xf2,0x87,0x30},
	{0xdc,0xb2,0x33,0xef,0x90,0x22},{0xde,0xb1,0x3a,0xe4,0x9d,0x2c},
	{0xe0,0x90,0xdd,0x3d,0x06,0x96},{0xe2,0x93,0xd4,0x36,0x0b,0x98},
	{0xe4,0x96,0xcf,0x2b,0x1c,0x8a},{0xe6,0x95,0xc6,0x20,0x11,0x84},
	{0xe8,0x9c,0xf9,0x11,0x32,0xae},{0xea,0x9f,0xf0,0x1a,0x3f,0xa0},
	{0xec,0x9a,0xeb,0x07,0x28,0xb2},{0xee,0x99,0xe2,0x0c,0x25,0xbc},
	{0xf0,0x88,0x95,0x65,0x6e,0xe6},{0xf2,0x8b,0x9c,0x6e,0x63,0xe8},
	{0xf4,0x8e,0x87,0x73,0x74,0xfa},{0xf6,0x8d,0x8e,0x78,0x79,0xf4},
	{0xf8,0x84,0xb1,0x49,0x5a,0xde},{0xfa,0x87,0xb8,0x42,0x57,0xd0},
	{0xfc,0x82,0xa3,0x5f,0x40,0xc2},{0xfe,0x81,0xaa,0x54,0x4d,0xcc},
	{0x1b,0x9b,0xec,0xf7,0xda,0x41},{0x19,0x98,0xe5,0xfc,0xd7,0x4f},
	{0x1f,0x9d,0xfe,0xe1,0xc0,0x5d},{0x1d,0x9e,0xf7,0xea,0xcd,0x53},
	{0x13,0x97,0xc8,0xdb,0xee,0x79},{0x11,0x94,0xc1,0xd0,0xe3,0x77},
	{0x17,0x91,0xda,0xcd,0xf4,0x65},{0x15,0x92,0xd3,0xc6,0xf9,0x6b},
	{0x0b,0x83,0xa4,0xaf,0xb2,0x31},{0x09,0x80,0xad,0xa4,0xbf,0x3f},
	{0x0f,0x85,0xb6,0xb9,0xa8,0x2d},{0x0d,0x86,0xbf,0xb2,0xa5,0x23},
	{0x03,0x8f,0x80,0x83,0x86,0x09},{0x01,0x8c,0x89,0x88,0x8b,0x07},
	{0x07,0x89,0x92,0x95,0x9c,0x15},{0x05,0x8a,0x9b,0x9e,0x91,0x1b},
	{0x3b,0xab,0x7c,0x47,0x0a,0xa1},{0x39,0xa8,0x75,0x4c,0x07,0xaf},
	{0x3f,0xad,0x6e,0x51,0x10,0xbd},{0x3d,0xae,0x67,0x5a,0x1d,0xb3},
	{0x33,0xa7,0x58,0x6b,0x3e,0x99},{0x31,0xa4,0x51,0x60,0x33,0x97},
	{0x37,0xa1,0x4a,0x7d,0x24,0x85},{0x35,0xa2,0x43,0x76,0x29,0x8b},
	{0x2b,0xb3,0x34,0x1f,0x62,0xd1},{0x29,0xb0,0x3d,0x14,0x6f,0xdf},
	{0x2f,0xb5,0x26,0x09,0x78,0xcd},{0x2d,0xb6,0x2f,0x02,0x75,0xc3},
	{0x23,0xbf,0x10,0x33,0x56,0xe9},{0x21,0xbc,0x19,0x38,0x5b,0xe7},
	{0x27,0xb9,0x02,0x25,0x4c,0xf5},{0x25,0xba,0x0b,0x2e,0x41,0xfb},
	{0x5b,0xfb,0xd7,0x8c,0x61,0x9a},{0x59,0xf8,0xde,0x87,0x6c,0x94},
	{0x5f,0xfd,0xc5,0x9a,0x7b,0x86},{0x5d,0xfe,0xcc,0x91,0x76,0x88},
	{0x53,0xf7,0xf3,0xa0,0x55,0xa2},{0x51,0xf4,0xfa,0xab,0x58,0xac},
	{0x57,0xf1,0xe1,0xb6,0x4f,0xbe},{0x55,0xf2,0xe8,0xbd,0x42,0xb0},
	{0x4b,0xe3,0x9f,0xd4,0x09,0xea},{0x49,0xe0,0x96,0xdf,0x04,0xe4},
	{0x4f,0xe5,0x8d,0xc2,0x13,0xf6},{0x4d,0xe6,0x84,0xc9,0x1e,0xf8},
	{0x43,0xef,0xbb,0xf8,0x3d,0xd2},{0x41,0xec,0xb2,0xf3,0x30,0xdc},
	{0x47,0xe9,0xa9,0xee,0x27,0xce},{0x45,0xea,0xa0,0xe5,0x2a,0xc0},
	{0x7b,0xcb,0x47,0x3c,0xb1,0x7a},{0x79,0xc8,0x4e,0x37,0xbc,0x74},
	{0x7f,0xcd,0x55,0x2a,0xab,0x66},{0x7d,0xce,0x5c,0x21,0xa6,0x68},
	{0x73,0xc7,0x63,0x10,0x85,0x42},{0x71,0xc4,0x6a,0x1b,0x88,0x4c},
	{0x77,0xc1,0x71,0x06,0x9f,0x5e},{0x75,0xc2,0x78,0x0d,0x92,0x50},
	{0x6b,0xd3,0x0f,0x64,0xd9,0x0a},{0x69,0xd0,0x06,0x6f,0xd4,0x04},
	{0x6f,0xd5,0x1d,0x72,0xc3,0x16},{0x6d,0xd6,0x14,0x79,0xce,0x18},
	{0x63,0xdf,0x2b,0x48,0xed,0x32},{0x61,0xdc,0x22,0x43,0xe0,0x3c},
	{0x67,0xd9,0x39,0x5e,0xf7,0x2e},{0x65,0xda,0x30,0x55,0xfa,0x20},
	{0x9b,0x5b,0x9a,0x01,0xb7,0xec},{0x99,0x58,0x93,0x0a,0xba,0xe2},
	{0x9f,0x5d,0x88,0x17,0xad,0xf0},{0x9d,0x5e,0x81,0x1c,0xa0,0xfe},
	{0x93,0x57,0xbe,0x2d,0x83,0xd4},{0x91,0x54,0xb7,0x26,0x8e,0xda},
	{0x97,0x51,0xac,0x3b,0x99,0xc8},{0x95,0x52,0xa5,0x30,0x94,0xc6},
	{0x8b,0x43,0xd2,0x59,0xdf,0x9c},{0x89,0x40,0xdb,0x52,0xd2,0x92},
	{0x8f,0x45,0xc0,0x4f,0xc5,0x80},{0x8d,0x46,0xc9,0x44,0xc8,0x8e},
	{0x83,0x4f,0xf6,0x75,0xeb,0xa4},{0x81,0x4c,0xff,0x7e,0xe6,0xaa},
	{0x87,0x49,0xe4,0x63,0xf1,0xb8},{0x85,0x4a,0xed,0x68,0xfc,0xb6},
	{0xbb,0x6b,0x0a,0xb1,0x67,0x0c},{0xb9,0x68,0x03,0xba,0x6a,0x02},
	{0xbf,0x6d,0x18,0xa7,0x7d,0x10},{0xbd,0x6e,0x11,0xac,0x70,0x1e},
	{0xb3,0x67,0x2e,0x9d,0x53,0x34},{0xb1,0x64,0x27,0x96,0x5e,0x3a},
	{0xb7,0x61,0x3c,0x8b,0x49,0x28},{0xb5,0x62,0x35,0x80,0x44,0x26},
	{0xab,0x73,0x42,0xe9,0x0f,0x7c},{0xa9,0x70,0x4b,0xe2,0x02,0x72},
	{0xaf,0x75,0x50,0xff,0x15,0x60},{0xad,0x76,0x59,0xf4,0x18,0x6e},
	{0xa3,0x7f,0x66,0xc5,0x3b,0x44},{0xa1,0x7c,0x6f,0xce,0x36,0x4a},
	{0xa7,0x79,0x74,0xd3,0x21,0x58},{0xa5,0x7a,0x7d,0xd8,0x2c,0x56},
	{0xdb,0x3b,0xa1,0x7a,0x0c,0x37},{0xd9,0x38,0xa8,0x71,0x01,0x39},
	{0xdf,0x3d,0xb3,0x6c,0x16,0x2b},{0xdd,0x3e,0xba,0x67,0x1b,0x25},
	{0xd3,0x37,0x85,0x56,0x38,0x0f},{0xd1,0x34,0x8c,0x5d,0x35,0x01},
	{0xd7,0x31,0x97,0x40,0x22,0x13},{0xd5,0x32,0x9e,0x4b,0x2f,0x1d},
	{0xcb,0x23,0xe9,0x22,0x64,0x47},{0xc9,0x20,0xe0,0x29,0x69,0x49},
	{0xcf,0x25,0xfb,0x34,0x7e,0x5b},{0xcd,0x26,0xf2,0x3f,0x73,0x55},
	{0xc3,0x2f,0xcd,0x0e,0x50,0x7f},{0xc1,0x2c,0xc4,0x05,0x5d,0x71},
	{0xc7,0x29,0xdf,0x18,0x4a,0x63},{0xc5,0x2a,0xd6,0x13,0x47,0x6d},
	{0xfb,0x0b,0x31,0xca,0xdc,0xd7},{0xf9,0x08,0x38,0xc1,0xd1,0xd9},
	{0xff,0x0d,0x23,0xdc,0xc6,0xcb},{0xfd,0x0e,0x2a,0xd7,0xcb,0xc5},
	{0xf3,0x07,0x15,0xe6,0xe8,0xef},{0xf1,0x04,0x1c,0xed,0xe5,0xe1},
	{0xf7,0x01,0x07,0xf0,0xf2,0xf3},{0xf5,0x02,0x0e,0xfb,0xff,0xfd},
	{0xeb,0x13,0x79,0x92,0xb4,0xa7},{0xe9,0x10,0x70,0x99,0xb9,0xa9},
	{0xef,0x15,0x6b,0x84,0xae,0xbb},{0xed,0x16,0x62,0x8f,0xa3,0xb5},
	{0xe3,0x1f,0x5d,0xbe,0x80,0x9f},{0xe1,0x1c,0x54,0xb5,0x8d,0x91},
	{0xe7,0x19,0x4f,0xa8,0x9a,0x83},{0xe5,0x1a,0x46,0xa3,0x97,0x8d}
};


static const WORD p_perm[18] = {
   0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,0xA4093822,0x299F31D0,0x082EFA98,
   0xEC4E6C89,0x452821E6,0x38D01377,0xBE5466CF,0x34E90C6C,0xC0AC29B7,0xC97C50DD,
   0x3F84D5B5,0xB5470917,0x9216D5D9,0x8979FB1B
};

static const WORD s_perm[4][256] = { {
   0xD1310BA6,0x98DFB5AC,0x2FFD72DB,0xD01ADFB7,0xB8E1AFED,0x6A267E96,0xBA7C9045,0xF12C7F99,
   0x24A19947,0xB3916CF7,0x0801F2E2,0x858EFC16,0x636920D8,0x71574E69,0xA458FEA3,0xF4933D7E,
   0x0D95748F,0x728EB658,0x718BCD58,0x82154AEE,0x7B54A41D,0xC25A59B5,0x9C30D539,0x2AF26013,
   0xC5D1B023,0x286085F0,0xCA417918,0xB8DB38EF,0x8E79DCB0,0x603A180E,0x6C9E0E8B,0xB01E8A3E,
   0xD71577C1,0xBD314B27,0x78AF2FDA,0x55605C60,0xE65525F3,0xAA55AB94,0x57489862,0x63E81440,
   0x55CA396A,0x2AAB10B6,0xB4CC5C34,0x1141E8CE,0xA15486AF,0x7C72E993,0xB3EE1411,0x636FBC2A,
   0x2BA9C55D,0x741831F6,0xCE5C3E16,0x9B87931E,0xAFD6BA33,0x6C24CF5C,0x7A325381,0x28958677,
   0x3B8F4898,0x6B4BB9AF,0xC4BFE81B,0x66282193,0x61D809CC,0xFB21A991,0x487CAC60,0x5DEC8032,
   0xEF845D5D,0xE98575B1,0xDC262302,0xEB651B88,0x23893E81,0xD396ACC5,0x0F6D6FF3,0x83F44239,
   0x2E0B4482,0xA4842004,0x69C8F04A,0x9E1F9B5E,0x21C66842,0xF6E96C9A,0x670C9C61,0xABD388F0,
   0x6A51A0D2,0xD8542F68,0x960FA728,0xAB5133A3,0x6EEF0B6C,0x137A3BE4,0xBA3BF050,0x7EFB2A98,
   0xA1F1651D,0x39AF0176,0x66CA593E,0x82430E88,0x8CEE8619,0x456F9FB4,0x7D84A5C3,0x3B8B5EBE,
   0xE06F75D8,0x85C12073,0x401A449F,0x56C16AA6,0x4ED3AA62,0x363F7706,0x1BFEDF72,0x429B023D,
   0x37D0D724,0xD00A1248,0xDB0FEAD3,0x49F1C09B,0x075372C9,0x80991B7B,0x25D479D8,0xF6E8DEF7,
   0xE3FE501A,0xB6794C3B,0x976CE0BD,0x04C006BA,0xC1A94FB6,0x409F60C4,0x5E5C9EC2,0x196A2463,
   0x68FB6FAF,0x3E6C53B5,0x1339B2EB,0x3B52EC6F,0x6DFC511F,0x9B30952C,0xCC814544,0xAF5EBD09,
   0xBEE3D004,0xDE334AFD,0x660F2807,0x192E4BB3,0xC0CBA857,0x45C8740F,0xD20B5F39,0xB9D3FBDB,
   0x5579C0BD,0x1A60320A,0xD6A100C6,0x402C7279,0x679F25FE,0xFB1FA3CC,0x8EA5E9F8,0xDB3222F8,
   0x3C7516DF,0xFD616B15,0x2F501EC8,0xAD0552AB,0x323DB5FA,0xFD238760,0x53317B48,0x3E00DF82,
   0x9E5C57BB,0xCA6F8CA0,0x1A87562E,0xDF1769DB,0xD542A8F6,0x287EFFC3,0xAC6732C6,0x8C4F5573,
   0x695B27B0,0xBBCA58C8,0xE1FFA35D,0xB8F011A0,0x10FA3D98,0xFD2183B8,0x4AFCB56C,0x2DD1D35B,
   0x9A53E479,0xB6F84565,0xD28E49BC,0x4BFB9790,0xE1DDF2DA,0xA4CB7E33,0x62FB1341,0xCEE4C6E8,
   0xEF20CADA,0x36774C01,0xD07E9EFE,0x2BF11FB4,0x95DBDA4D,0xAE909198,0xEAAD8E71,0x6B93D5A0,
   0xD08ED1D0,0xAFC725E0,0x8E3C5B2F,0x8E7594B7,0x8FF6E2FB,0xF2122B64,0x8888B812,0x900DF01C,
   0x4FAD5EA0,0x688FC31C,0xD1CFF191,0xB3A8C1AD,0x2F2F2218,0xBE0E1777,0xEA752DFE,0x8B021FA1,
   0xE5A0CC0F,0xB56F74E8,0x18ACF3D6,0xCE89E299,0xB4A84FE0,0xFD13E0B7,0x7CC43B81,0xD2ADA8D9,
   0x165FA266,0x80957705,0x93CC7314,0x211A1477,0xE6AD2065,0x77B5FA86,0xC75442F5,0xFB9D35CF,
   0xEBCDAF0C,0x7B3E89A0,0xD6411BD3,0xAE1E7E49,0x00250E2D,0x2071B35E,0x226800BB,0x57B8E0AF,
   0x2464369B,0xF009B91E,0x5563911D,0x59DFA6AA,0x78C14389,0xD95A537F,0x207D5BA2,0x02E5B9C5,
   0x83260376,0x6295CFA9,0x11C81968,0x4E734A41,0xB3472DCA,0x7B14A94A,0x1B510052,0x9A532915,
   0xD60F573F,0xBC9BC6E4,0x2B60A476,0x81E67400,0x08BA6FB5,0x571BE91F,0xF296EC6B,0x2A0DD915,
   0xB6636521,0xE7B9F9B6,0xFF34052E,0xC5855664,0x53B02D5D,0xA99F8FA1,0x08BA4799,0x6E85076A
},{
   0x4B7A70E9,0xB5B32944,0xDB75092E,0xC4192623,0xAD6EA6B0,0x49A7DF7D,0x9CEE60B8,0x8FEDB266,
   0xECAA8C71,0x699A17FF,0x5664526C,0xC2B19EE1,0x193602A5,0x75094C29,0xA0591340,0xE4183A3E,
   0x3F54989A,0x5B429D65,0x6B8FE4D6,0x99F73FD6,0xA1D29C07,0xEFE830F5,0x4D2D38E6,0xF0255DC1,
   0x4CDD2086,0x8470EB26,0x6382E9C6,0x021ECC5E,0x09686B3F,0x3EBAEFC9,0x3C971814,0x6B6A70A1,
   0x687F3584,0x52A0E286,0xB79C5305,0xAA500737,0x3E07841C,0x7FDEAE5C,0x8E7D44EC,0x5716F2B8,
   0xB03ADA37,0xF0500C0D,0xF01C1F04,0x0200B3FF,0xAE0CF51A,0x3CB574B2,0x25837A58,0xDC0921BD,
   0xD19113F9,0x7CA92FF6,0x94324773,0x22F54701,0x3AE5E581,0x37C2DADC,0xC8B57634,0x9AF3DDA7,
   0xA9446146,0x0FD0030E,0xECC8C73E,0xA4751E41,0xE238CD99,0x3BEA0E2F,0x3280BBA1,0x183EB331,
   0x4E548B38,0x4F6DB908,0x6F420D03,0xF60A04BF,0x2CB81290,0x24977C79,0x5679B072,0xBCAF89AF,
   0xDE9A771F,0xD9930810,0xB38BAE12,0xDCCF3F2E,0x5512721F,0x2E6B7124,0x501ADDE6,0x9F84CD87,
   0x7A584718,0x7408DA17,0xBC9F9ABC,0xE94B7D8C,0xEC7AEC3A,0xDB851DFA,0x63094366,0xC464C3D2,
   0xEF1C1847,0x3215D908,0xDD433B37,0x24C2BA16,0x12A14D43,0x2A65C451,0x50940002,0x133AE4DD,
   0x71DFF89E,0x10314E55,0x81AC77D6,0x5F11199B,0x043556F1,0xD7A3C76B,0x3C11183B,0x5924A509,
   0xF28FE6ED,0x97F1FBFA,0x9EBABF2C,0x1E153C6E,0x86E34570,0xEAE96FB1,0x860E5E0A,0x5A3E2AB3,
   0x771FE71C,0x4E3D06FA,0x2965DCB9,0x99E71D0F,0x803E89D6,0x5266C825,0x2E4CC978,0x9C10B36A,
   0xC6150EBA,0x94E2EA78,0xA5FC3C53,0x1E0A2DF4,0xF2F74EA7,0x361D2B3D,0x1939260F,0x19C27960,
   0x5223A708,0xF71312B6,0xEBADFE6E,0xEAC31F66,0xE3BC4595,0xA67BC883,0xB17F37D1,0x018CFF28,
   0xC332DDEF,0xBE6C5AA5,0x65582185,0x68AB9802,0xEECEA50F,0xDB2F953B,0x2AEF7DAD,0x5B6E2F84,
   0x1521B628,0x29076170,0xECDD4775,0x619F1510,0x13CCA830,0xEB61BD96,0x0334FE1E,0xAA0363CF,
   0xB5735C90,0x4C70A239,0xD59E9E0B,0xCBAADE14,0xEECC86BC,0x60622CA7,0x9CAB5CAB,0xB2F3846E,
   0x648B1EAF,0x19BDF0CA,0xA02369B9,0x655ABB50,0x40685A32,0x3C2AB4B3,0x319EE9D5,0xC021B8F7,
   0x9B540B19,0x875FA099,0x95F7997E,0x623D7DA8,0xF837889A,0x97E32D77,0x11ED935F,0x16681281,
   0x0E358829,0xC7E61FD6,0x96DEDFA1,0x7858BA99,0x57F584A5,0x1B227263,0x9B83C3FF,0x1AC24696,
   0xCDB30AEB,0x532E3054,0x8FD948E4,0x6DBC3128,0x58EBF2EF,0x34C6FFEA,0xFE28ED61,0xEE7C3C73,
   0x5D4A14D9,0xE864B7E3,0x42105D14,0x203E13E0,0x45EEE2B6,0xA3AAABEA,0xDB6C4F15,0xFACB4FD0,
   0xC742F442,0xEF6ABBB5,0x654F3B1D,0x41CD2105,0xD81E799E,0x86854DC7,0xE44B476A,0x3D816250,
   0xCF62A1F2,0x5B8D2646,0xFC8883A0,0xC1C7B6A3,0x7F1524C3,0x69CB7492,0x47848A0B,0x5692B285,
   0x095BBF00,0xAD19489D,0x1462B174,0x23820E00,0x58428D2A,0x0C55F5EA,0x1DADF43E,0x233F7061,
   0x3372F092,0x8D937E41,0xD65FECF1,0x6C223BDB,0x7CDE3759,0xCBEE7460,0x4085F2A7,0xCE77326E,
   0xA6078084,0x19F8509E,0xE8EFD855,0x61D99735,0xA969A7AA,0xC50C06C2,0x5A04ABFC,0x800BCADC,
   0x9E447A2E,0xC3453484,0xFDD56705,0x0E1E9EC9,0xDB73DBD3,0x105588CD,0x675FDA79,0xE3674340,
   0xC5C43465,0x713E38D8,0x3D28F89E,0xF16DFF20,0x153E21E7,0x8FB03D4A,0xE6E39F2B,0xDB83ADF7
},{
   0xE93D5A68,0x948140F7,0xF64C261C,0x94692934,0x411520F7,0x7602D4F7,0xBCF46B2E,0xD4A20068,
   0xD4082471,0x3320F46A,0x43B7D4B7,0x500061AF,0x1E39F62E,0x97244546,0x14214F74,0xBF8B8840,
   0x4D95FC1D,0x96B591AF,0x70F4DDD3,0x66A02F45,0xBFBC09EC,0x03BD9785,0x7FAC6DD0,0x31CB8504,
   0x96EB27B3,0x55FD3941,0xDA2547E6,0xABCA0A9A,0x28507825,0x530429F4,0x0A2C86DA,0xE9B66DFB,
   0x68DC1462,0xD7486900,0x680EC0A4,0x27A18DEE,0x4F3FFEA2,0xE887AD8C,0xB58CE006,0x7AF4D6B6,
   0xAACE1E7C,0xD3375FEC,0xCE78A399,0x406B2A42,0x20FE9E35,0xD9F385B9,0xEE39D7AB,0x3B124E8B,
   0x1DC9FAF7,0x4B6D1856,0x26A36631,0xEAE397B2,0x3A6EFA74,0xDD5B4332,0x6841E7F7,0xCA7820FB,
   0xFB0AF54E,0xD8FEB397,0x454056AC,0xBA489527,0x55533A3A,0x20838D87,0xFE6BA9B7,0xD096954B,
   0x55A867BC,0xA1159A58,0xCCA92963,0x99E1DB33,0xA62A4A56,0x3F3125F9,0x5EF47E1C,0x9029317C,
   0xFDF8E802,0x04272F70,0x80BB155C,0x05282CE3,0x95C11548,0xE4C66D22,0x48C1133F,0xC70F86DC,
   0x07F9C9EE,0x41041F0F,0x404779A4,0x5D886E17,0x325F51EB,0xD59BC0D1,0xF2BCC18F,0x41113564,
   0x257B7834,0x602A9C60,0xDFF8E8A3,0x1F636C1B,0x0E12B4C2,0x02E1329E,0xAF664FD1,0xCAD18115,
   0x6B2395E0,0x333E92E1,0x3B240B62,0xEEBEB922,0x85B2A20E,0xE6BA0D99,0xDE720C8C,0x2DA2F728,
   0xD0127845,0x95B794FD,0x647D0862,0xE7CCF5F0,0x5449A36F,0x877D48FA,0xC39DFD27,0xF33E8D1E,
   0x0A476341,0x992EFF74,0x3A6F6EAB,0xF4F8FD37,0xA812DC60,0xA1EBDDF8,0x991BE14C,0xDB6E6B0D,
   0xC67B5510,0x6D672C37,0x2765D43B,0xDCD0E804,0xF1290DC7,0xCC00FFA3,0xB5390F92,0x690FED0B,
   0x667B9FFB,0xCEDB7D9C,0xA091CF0B,0xD9155EA3,0xBB132F88,0x515BAD24,0x7B9479BF,0x763BD6EB,
   0x37392EB3,0xCC115979,0x8026E297,0xF42E312D,0x6842ADA7,0xC66A2B3B,0x12754CCC,0x782EF11C,
   0x6A124237,0xB79251E7,0x06A1BBE6,0x4BFB6350,0x1A6B1018,0x11CAEDFA,0x3D25BDD8,0xE2E1C3C9,
   0x44421659,0x0A121386,0xD90CEC6E,0xD5ABEA2A,0x64AF674E,0xDA86A85F,0xBEBFE988,0x64E4C3FE,
   0x9DBC8057,0xF0F7C086,0x60787BF8,0x6003604D,0xD1FD8346,0xF6381FB0,0x7745AE04,0xD736FCCC,
   0x83426B33,0xF01EAB71,0xB0804187,0x3C005E5F,0x77A057BE,0xBDE8AE24,0x55464299,0xBF582E61,
   0x4E58F48F,0xF2DDFDA2,0xF474EF38,0x8789BDC2,0x5366F9C3,0xC8B38E74,0xB475F255,0x46FCD9B9,
   0x7AEB2661,0x8B1DDF84,0x846A0E79,0x915F95E2,0x466E598E,0x20B45770,0x8CD55591,0xC902DE4C,
   0xB90BACE1,0xBB8205D0,0x11A86248,0x7574A99E,0xB77F19B6,0xE0A9DC09,0x662D09A1,0xC4324633,
   0xE85A1F02,0x09F0BE8C,0x4A99A025,0x1D6EFE10,0x1AB93D1D,0x0BA5A4DF,0xA186F20F,0x2868F169,
   0xDCB7DA83,0x573906FE,0xA1E2CE9B,0x4FCD7F52,0x50115E01,0xA70683FA,0xA002B5C4,0x0DE6D027,
   0x9AF88C27,0x773F8641,0xC3604C06,0x61A806B5,0xF0177A28,0xC0F586E0,0x006058AA,0x30DC7D62,
   0x11E69ED7,0x2338EA63,0x53C2DD94,0xC2C21634,0xBBCBEE56,0x90BCB6DE,0xEBFC7DA1,0xCE591D76,
   0x6F05E409,0x4B7C0188,0x39720A3D,0x7C927C24,0x86E3725F,0x724D9DB9,0x1AC15BB4,0xD39EB8FC,
   0xED545578,0x08FCA5B5,0xD83D7CD3,0x4DAD0FC4,0x1E50EF5E,0xB161E6F8,0xA28514D9,0x6C51133C,
   0x6FD5C7E7,0x56E14EC4,0x362ABFCE,0xDDC6C837,0xD79A3234,0x92638212,0x670EFA8E,0x406000E0
},{
   0x3A39CE37,0xD3FAF5CF,0xABC27737,0x5AC52D1B,0x5CB0679E,0x4FA33742,0xD3822740,0x99BC9BBE,
   0xD5118E9D,0xBF0F7315,0xD62D1C7E,0xC700C47B,0xB78C1B6B,0x21A19045,0xB26EB1BE,0x6A366EB4,
   0x5748AB2F,0xBC946E79,0xC6A376D2,0x6549C2C8,0x530FF8EE,0x468DDE7D,0xD5730A1D,0x4CD04DC6,
   0x2939BBDB,0xA9BA4650,0xAC9526E8,0xBE5EE304,0xA1FAD5F0,0x6A2D519A,0x63EF8CE2,0x9A86EE22,
   0xC089C2B8,0x43242EF6,0xA51E03AA,0x9CF2D0A4,0x83C061BA,0x9BE96A4D,0x8FE51550,0xBA645BD6,
   0x2826A2F9,0xA73A3AE1,0x4BA99586,0xEF5562E9,0xC72FEFD3,0xF752F7DA,0x3F046F69,0x77FA0A59,
   0x80E4A915,0x87B08601,0x9B09E6AD,0x3B3EE593,0xE990FD5A,0x9E34D797,0x2CF0B7D9,0x022B8B51,
   0x96D5AC3A,0x017DA67D,0xD1CF3ED6,0x7C7D2D28,0x1F9F25CF,0xADF2B89B,0x5AD6B472,0x5A88F54C,
   0xE029AC71,0xE019A5E6,0x47B0ACFD,0xED93FA9B,0xE8D3C48D,0x283B57CC,0xF8D56629,0x79132E28,
   0x785F0191,0xED756055,0xF7960E44,0xE3D35E8C,0x15056DD4,0x88F46DBA,0x03A16125,0x0564F0BD,
   0xC3EB9E15,0x3C9057A2,0x97271AEC,0xA93A072A,0x1B3F6D9B,0x1E6321F5,0xF59C66FB,0x26DCF319,
   0x7533D928,0xB155FDF5,0x03563482,0x8ABA3CBB,0x28517711,0xC20AD9F8,0xABCC5167,0xCCAD925F,
   0x4DE81751,0x3830DC8E,0x379D5862,0x9320F991,0xEA7A90C2,0xFB3E7BCE,0x5121CE64,0x774FBE32,
   0xA8B6E37E,0xC3293D46,0x48DE5369,0x6413E680,0xA2AE0810,0xDD6DB224,0x69852DFD,0x09072166,
   0xB39A460A,0x6445C0DD,0x586CDECF,0x1C20C8AE,0x5BBEF7DD,0x1B588D40,0xCCD2017F,0x6BB4E3BB,
   0xDDA26A7E,0x3A59FF45,0x3E350A44,0xBCB4CDD5,0x72EACEA8,0xFA6484BB,0x8D6612AE,0xBF3C6F47,
   0xD29BE463,0x542F5D9E,0xAEC2771B,0xF64E6370,0x740E0D8D,0xE75B1357,0xF8721671,0xAF537D5D,
   0x4040CB08,0x4EB4E2CC,0x34D2466A,0x0115AF84,0xE1B00428,0x95983A1D,0x06B89FB4,0xCE6EA048,
   0x6F3F3B82,0x3520AB82,0x011A1D4B,0x277227F8,0x611560B1,0xE7933FDC,0xBB3A792B,0x344525BD,
   0xA08839E1,0x51CE794B,0x2F32C9B7,0xA01FBAC9,0xE01CC87E,0xBCC7D1F6,0xCF0111C3,0xA1E8AAC7,
   0x1A908749,0xD44FBD9A,0xD0DADECB,0xD50ADA38,0x0339C32A,0xC6913667,0x8DF9317C,0xE0B12B4F,
   0xF79E59B7,0x43F5BB3A,0xF2D519FF,0x27D9459C,0xBF97222C,0x15E6FC2A,0x0F91FC71,0x9B941525,
   0xFAE59361,0xCEB69CEB,0xC2A86459,0x12BAA8D1,0xB6C1075E,0xE3056A0C,0x10D25065,0xCB03A442,
   0xE0EC6E0E,0x1698DB3B,0x4C98A0BE,0x3278E964,0x9F1F9532,0xE0D392DF,0xD3A0342B,0x8971F21E,
   0x1B0A7441,0x4BA3348C,0xC5BE7120,0xC37632D8,0xDF359F8D,0x9B992F2E,0xE60B6F47,0x0FE3F11D,
   0xE54CDA54,0x1EDAD891,0xCE6279CF,0xCD3E7E6F,0x1618B166,0xFD2C1D05,0x848FD2C5,0xF6FB2299,
   0xF523F357,0xA6327623,0x93A83531,0x56CCCD02,0xACF08162,0x5A75EBB5,0x6E163697,0x88D273CC,
   0xDE966292,0x81B949D0,0x4C50901B,0x71C65614,0xE6C6C7BD,0x327A140A,0x45E1D006,0xC3F27B9A,
   0xC9AA53FD,0x62A80F00,0xBB25BFE2,0x35BDD2F6,0x71126905,0xB2040222,0xB6CBCF7C,0xCD769C2B,
   0x53113EC0,0x1640E3D3,0x38ABBD60,0x2547ADF0,0xBA38209C,0xF746CE76,0x77AFA1C5,0x20756060,
   0x85CBFE4E,0x8AE88DD8,0x7AAAF9B0,0x4CF9AA7E,0x1948C25C,0x02FB8A8C,0x01C36AE4,0xD6EBE1F9,
   0x90D4F869,0xA65CDEA0,0x3F09252D,0xC208E69F,0xB74E6132,0xCE77E25B,0x578FDFE3,0x3AC372E6
} };

/*********************** FUNCTION DEFINITIONS ***********************/
void blowfish_encrypt(const BYTE in[], BYTE out[], const BLOWFISH_KEY *keystruct)
{
   WORD l,r,t; //,i;

   l = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | (in[3]);
   r = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | (in[7]);

   ITERATION(l,r,t,0);
   ITERATION(l,r,t,1);
   ITERATION(l,r,t,2);
   ITERATION(l,r,t,3);
   ITERATION(l,r,t,4);
   ITERATION(l,r,t,5);
   ITERATION(l,r,t,6);
   ITERATION(l,r,t,7);
   ITERATION(l,r,t,8);
   ITERATION(l,r,t,9);
   ITERATION(l,r,t,10);
   ITERATION(l,r,t,11);
   ITERATION(l,r,t,12);
   ITERATION(l,r,t,13);
   ITERATION(l,r,t,14);
   l ^= keystruct->p[15]; F(l,t); r^= t; //Last iteration has no swap()
   r ^= keystruct->p[16];
   l ^= keystruct->p[17];

   out[0] = l >> 24;
   out[1] = l >> 16;
   out[2] = l >> 8;
   out[3] = l;
   out[4] = r >> 24;
   out[5] = r >> 16;
   out[6] = r >> 8;
   out[7] = r;
}

void blowfish_decrypt(const BYTE in[], BYTE out[], const BLOWFISH_KEY *keystruct)
{
   WORD l,r,t; //,i;

   l = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | (in[3]);
   r = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | (in[7]);

   ITERATION(l,r,t,17);
   ITERATION(l,r,t,16);
   ITERATION(l,r,t,15);
   ITERATION(l,r,t,14);
   ITERATION(l,r,t,13);
   ITERATION(l,r,t,12);
   ITERATION(l,r,t,11);
   ITERATION(l,r,t,10);
   ITERATION(l,r,t,9);
   ITERATION(l,r,t,8);
   ITERATION(l,r,t,7);
   ITERATION(l,r,t,6);
   ITERATION(l,r,t,5);
   ITERATION(l,r,t,4);
   ITERATION(l,r,t,3);
   l ^= keystruct->p[2]; F(l,t); r^= t; //Last iteration has no swap()
   r ^= keystruct->p[1];
   l ^= keystruct->p[0];

   out[0] = l >> 24;
   out[1] = l >> 16;
   out[2] = l >> 8;
   out[3] = l;
   out[4] = r >> 24;
   out[5] = r >> 16;
   out[6] = r >> 8;
   out[7] = r;
}

void blowfish_key_setup(const BYTE user_key[], BLOWFISH_KEY *keystruct, size_t len)
{
   BYTE block[8];
   int idx,idx2;

   // Copy over the constant init array vals (so the originals aren't destroyed).
   memcpy(keystruct->p,p_perm,sizeof(WORD) * 18);
   memcpy(keystruct->s,s_perm,sizeof(WORD) * 1024);

   // Combine the key with the P box. Assume key is standard 448 bits (56 bytes) or less.
   for (idx = 0, idx2 = 0; idx < 18; ++idx, idx2 += 4)
      keystruct->p[idx] ^= (user_key[idx2 % len] << 24) | (user_key[(idx2+1) % len] << 16)
                           | (user_key[(idx2+2) % len] << 8) | (user_key[(idx2+3) % len]);
   // Re-calculate the P box.
   memset(block, 0, 8);
   for (idx = 0; idx < 18; idx += 2) {
      blowfish_encrypt(block,block,keystruct);
      keystruct->p[idx] = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3];
      keystruct->p[idx+1]=(block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7];
   }
   // Recalculate the S-boxes.
   for (idx = 0; idx < 4; ++idx) {
      for (idx2 = 0; idx2 < 256; idx2 += 2) {
         blowfish_encrypt(block,block,keystruct);
         keystruct->s[idx][idx2] = (block[0] << 24) | (block[1] << 16) |
                                   (block[2] << 8) | block[3];
         keystruct->s[idx][idx2+1] = (block[4] << 24) | (block[5] << 16) |
                                     (block[6] << 8) | block[7];
      }
   }
}





/*********************** FUNCTION DEFINITIONS ***********************/
// XORs the in and out buffers, storing the result in out. Length is in bytes.
void xor_buf(const BYTE in[], BYTE out[], size_t len)
{
	size_t idx;

	for (idx = 0; idx < len; idx++)
		out[idx] ^= in[idx];
}

/*******************
* AES - CBC
*******************/
int aes_encrypt_cbc(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[])
{
	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
	int blocks, idx;

	if (in_len % AES_BLOCK_SIZE != 0)
		return(FALSE);

	blocks = in_len / AES_BLOCK_SIZE;

	memcpy(iv_buf, iv, AES_BLOCK_SIZE);

	for (idx = 0; idx < blocks; idx++) {
		memcpy(buf_in, &in[idx * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
		xor_buf(iv_buf, buf_in, AES_BLOCK_SIZE);
		aes_encrypt(buf_in, buf_out, key, keysize);
		memcpy(&out[idx * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
		memcpy(iv_buf, buf_out, AES_BLOCK_SIZE);
	}

	return(TRUE);
}

int aes_encrypt_cbc_mac(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[])
{
	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
	int blocks, idx;

	if (in_len % AES_BLOCK_SIZE != 0)
		return(FALSE);

	blocks = in_len / AES_BLOCK_SIZE;

	memcpy(iv_buf, iv, AES_BLOCK_SIZE);

	for (idx = 0; idx < blocks; idx++) {
		memcpy(buf_in, &in[idx * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
		xor_buf(iv_buf, buf_in, AES_BLOCK_SIZE);
		aes_encrypt(buf_in, buf_out, key, keysize);
		memcpy(iv_buf, buf_out, AES_BLOCK_SIZE);
		// Do not output all encrypted blocks.
	}

	memcpy(out, buf_out, AES_BLOCK_SIZE);   // Only output the last block.

	return(TRUE);
}

int aes_decrypt_cbc(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[])
{
	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
	int blocks, idx;

	if (in_len % AES_BLOCK_SIZE != 0)
		return(FALSE);

	blocks = in_len / AES_BLOCK_SIZE;

	memcpy(iv_buf, iv, AES_BLOCK_SIZE);

	for (idx = 0; idx < blocks; idx++) {
		memcpy(buf_in, &in[idx * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
		aes_decrypt(buf_in, buf_out, key, keysize);
		xor_buf(iv_buf, buf_out, AES_BLOCK_SIZE);
		memcpy(&out[idx * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
		memcpy(iv_buf, buf_in, AES_BLOCK_SIZE);
	}

	return(TRUE);
}

/*******************
* AES - CTR
*******************/
void increment_iv(BYTE iv[], int counter_size)
{
	int idx;

	// Use counter_size bytes at the end of the IV as the big-endian integer to increment.
	for (idx = AES_BLOCK_SIZE - 1; idx >= AES_BLOCK_SIZE - counter_size; idx--) {
		iv[idx]++;
		if (iv[idx] != 0 || idx == AES_BLOCK_SIZE - counter_size)
			break;
	}
}

// Performs the encryption in-place, the input and output buffers may be the same.
// Input may be an arbitrary length (in bytes).
void aes_encrypt_ctr(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[])
{
	size_t idx = 0, last_block_length;
	BYTE iv_buf[AES_BLOCK_SIZE], out_buf[AES_BLOCK_SIZE];

	if (in != out)
		memcpy(out, in, in_len);

	memcpy(iv_buf, iv, AES_BLOCK_SIZE);
	last_block_length = in_len - AES_BLOCK_SIZE;

	if (in_len > AES_BLOCK_SIZE) {
		for (idx = 0; idx < last_block_length; idx += AES_BLOCK_SIZE) {
			aes_encrypt(iv_buf, out_buf, key, keysize);
			xor_buf(out_buf, &out[idx], AES_BLOCK_SIZE);
			increment_iv(iv_buf, AES_BLOCK_SIZE);
		}
	}

	aes_encrypt(iv_buf, out_buf, key, keysize);
	xor_buf(out_buf, &out[idx], in_len - idx);   // Use the Most Significant bytes.
}

void aes_decrypt_ctr(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[])
{
	// CTR encryption is its own inverse function.
	aes_encrypt_ctr(in, in_len, out, key, keysize, iv);
}

/*******************
* AES - CCM
*******************/
// out_len = payload_len + assoc_len
int aes_encrypt_ccm(const BYTE payload[], WORD payload_len, const BYTE assoc[], unsigned short assoc_len,
                    const BYTE nonce[], unsigned short nonce_len, BYTE out[], WORD *out_len,
                    WORD mac_len, const BYTE key_str[], int keysize)
{
	BYTE temp_iv[AES_BLOCK_SIZE], counter[AES_BLOCK_SIZE], mac[16], *buf;
	int end_of_buf, payload_len_store_size;
	WORD key[60];

	if (mac_len != 4 && mac_len != 6 && mac_len != 8 && mac_len != 10 &&
	   mac_len != 12 && mac_len != 14 && mac_len != 16)
		return(FALSE);

	if (nonce_len < 7 || nonce_len > 13)
		return(FALSE);

	if (assoc_len > 32768 /* = 2^15 */)
		return(FALSE);

	buf = (BYTE*)malloc(payload_len + assoc_len + 48 /*Round both payload and associated data up a block size and add an extra block.*/);
	if (! buf)
		return(FALSE);

	// Prepare the key for usage.
	aes_key_setup(key_str, key, keysize);

	// Format the first block of the formatted data.
	payload_len_store_size = AES_BLOCK_SIZE - 1 - nonce_len;
	ccm_prepare_first_format_blk(buf, assoc_len, payload_len, payload_len_store_size, mac_len, nonce, nonce_len);
	end_of_buf = AES_BLOCK_SIZE;

	// Format the Associated Data, aka, assoc[].
	ccm_format_assoc_data(buf, &end_of_buf, assoc, assoc_len);

	// Format the Payload, aka payload[].
	ccm_format_payload_data(buf, &end_of_buf, payload, payload_len);

	// Create the first counter block.
	ccm_prepare_first_ctr_blk(counter, nonce, nonce_len, payload_len_store_size);

	// Perform the CBC operation with an IV of zeros on the formatted buffer to calculate the MAC.
	memset(temp_iv, 0, AES_BLOCK_SIZE);
	aes_encrypt_cbc_mac(buf, end_of_buf, mac, key, keysize, temp_iv);

	// Copy the Payload and MAC to the output buffer.
	memcpy(out, payload, payload_len);
	memcpy(&out[payload_len], mac, mac_len);

	// Encrypt the Payload with CTR mode with a counter starting at 1.
	memcpy(temp_iv, counter, AES_BLOCK_SIZE);
	increment_iv(temp_iv, AES_BLOCK_SIZE - 1 - mac_len);   // Last argument is the byte size of the counting portion of the counter block. /*BUG?*/
	aes_encrypt_ctr(out, payload_len, out, key, keysize, temp_iv);

	// Encrypt the MAC with CTR mode with a counter starting at 0.
	aes_encrypt_ctr(&out[payload_len], mac_len, &out[payload_len], key, keysize, counter);

	free(buf);
	*out_len = payload_len + mac_len;

	return(TRUE);
}

// plaintext_len = ciphertext_len - mac_len
// Needs a flag for whether the MAC matches.
int aes_decrypt_ccm(const BYTE ciphertext[], WORD ciphertext_len, const BYTE assoc[], unsigned short assoc_len,
                    const BYTE nonce[], unsigned short nonce_len, BYTE plaintext[], WORD *plaintext_len,
                    WORD mac_len, int *mac_auth, const BYTE key_str[], int keysize)
{
	BYTE temp_iv[AES_BLOCK_SIZE], counter[AES_BLOCK_SIZE], mac[16], mac_buf[16], *buf;
	int end_of_buf, plaintext_len_store_size;
	WORD key[60];

	if (ciphertext_len <= mac_len)
		return(FALSE);

	buf = (BYTE*)malloc(assoc_len + ciphertext_len /*ciphertext_len = plaintext_len + mac_len*/ + 48);
	if (! buf)
		return(FALSE);

	// Prepare the key for usage.
	aes_key_setup(key_str, key, keysize);

	// Copy the plaintext and MAC to the output buffers.
	*plaintext_len = ciphertext_len - mac_len;
	plaintext_len_store_size = AES_BLOCK_SIZE - 1 - nonce_len;
	memcpy(plaintext, ciphertext, *plaintext_len);
	memcpy(mac, &ciphertext[*plaintext_len], mac_len);

	// Prepare the first counter block for use in decryption.
	ccm_prepare_first_ctr_blk(counter, nonce, nonce_len, plaintext_len_store_size);

	// Decrypt the Payload with CTR mode with a counter starting at 1.
	memcpy(temp_iv, counter, AES_BLOCK_SIZE);
	increment_iv(temp_iv, AES_BLOCK_SIZE - 1 - mac_len);   // (AES_BLOCK_SIZE - 1 - mac_len) is the byte size of the counting portion of the counter block.
	aes_decrypt_ctr(plaintext, *plaintext_len, plaintext, key, keysize, temp_iv);

	// Setting mac_auth to NULL disables the authentication check.
	if (mac_auth != NULL) {
		// Decrypt the MAC with CTR mode with a counter starting at 0.
		aes_decrypt_ctr(mac, mac_len, mac, key, keysize, counter);

		// Format the first block of the formatted data.
		plaintext_len_store_size = AES_BLOCK_SIZE - 1 - nonce_len;
		ccm_prepare_first_format_blk(buf, assoc_len, *plaintext_len, plaintext_len_store_size, mac_len, nonce, nonce_len);
		end_of_buf = AES_BLOCK_SIZE;

		// Format the Associated Data into the authentication buffer.
		ccm_format_assoc_data(buf, &end_of_buf, assoc, assoc_len);

		// Format the Payload into the authentication buffer.
		ccm_format_payload_data(buf, &end_of_buf, plaintext, *plaintext_len);

		// Perform the CBC operation with an IV of zeros on the formatted buffer to calculate the MAC.
		memset(temp_iv, 0, AES_BLOCK_SIZE);
		aes_encrypt_cbc_mac(buf, end_of_buf, mac_buf, key, keysize, temp_iv);

		// Compare the calculated MAC against the MAC embedded in the ciphertext to see if they are the same.
		if (! memcmp(mac, mac_buf, mac_len)) {
			*mac_auth = TRUE;
		}
		else {
			*mac_auth = FALSE;
			memset(plaintext, 0, *plaintext_len);
		}
	}

	free(buf);

	return(TRUE);
}

// Creates the first counter block. First byte is flags, then the nonce, then the incremented part.
void ccm_prepare_first_ctr_blk(BYTE counter[], const BYTE nonce[], int nonce_len, int payload_len_store_size)
{
	memset(counter, 0, AES_BLOCK_SIZE);
	counter[0] = (payload_len_store_size - 1) & 0x07;
	memcpy(&counter[1], nonce, nonce_len);
}

void ccm_prepare_first_format_blk(BYTE buf[], int assoc_len, int payload_len, int payload_len_store_size, int mac_len, const BYTE nonce[], int nonce_len)
{
	// Set the flags for the first byte of the first block.
	buf[0] = ((((mac_len - 2) / 2) & 0x07) << 3) | ((payload_len_store_size - 1) & 0x07);
	if (assoc_len > 0)
		buf[0] += 0x40;
	// Format the rest of the first block, storing the nonce and the size of the payload.
	memcpy(&buf[1], nonce, nonce_len);
	memset(&buf[1 + nonce_len], 0, AES_BLOCK_SIZE - 1 - nonce_len);
	buf[15] = payload_len & 0x000000FF;
	buf[14] = (payload_len >> 8) & 0x000000FF;
}

void ccm_format_assoc_data(BYTE buf[], int *end_of_buf, const BYTE assoc[], int assoc_len)
{
	int pad;

	buf[*end_of_buf + 1] = assoc_len & 0x00FF;
	buf[*end_of_buf] = (assoc_len >> 8) & 0x00FF;
	*end_of_buf += 2;
	memcpy(&buf[*end_of_buf], assoc, assoc_len);
	*end_of_buf += assoc_len;
	pad = AES_BLOCK_SIZE - (*end_of_buf % AES_BLOCK_SIZE); /*BUG?*/
	memset(&buf[*end_of_buf], 0, pad);
	*end_of_buf += pad;
}

void ccm_format_payload_data(BYTE buf[], int *end_of_buf, const BYTE payload[], int payload_len)
{
	int pad;

	memcpy(&buf[*end_of_buf], payload, payload_len);
	*end_of_buf += payload_len;
	pad = *end_of_buf % AES_BLOCK_SIZE;
	if (pad != 0)
		pad = AES_BLOCK_SIZE - pad;
	memset(&buf[*end_of_buf], 0, pad);
	*end_of_buf += pad;
}

/*******************
* AES
*******************/
/////////////////
// KEY EXPANSION
/////////////////

// Substitutes a word using the AES S-Box.
WORD SubWord(WORD word)
{
	unsigned int result;

	result = (int)aes_sbox[(word >> 4) & 0x0000000F][word & 0x0000000F];
	result += (int)aes_sbox[(word >> 12) & 0x0000000F][(word >> 8) & 0x0000000F] << 8;
	result += (int)aes_sbox[(word >> 20) & 0x0000000F][(word >> 16) & 0x0000000F] << 16;
	result += (int)aes_sbox[(word >> 28) & 0x0000000F][(word >> 24) & 0x0000000F] << 24;
	return(result);
}

// Performs the action of generating the keys that will be used in every round of
// encryption. "key" is the user-supplied input key, "w" is the output key schedule,
// "keysize" is the length in bits of "key", must be 128, 192, or 256.
void aes_key_setup(const BYTE key[], WORD w[], int keysize)
{
	int Nb=4,Nr,Nk,idx;
	WORD temp,Rcon[]={0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,
	                  0x40000000,0x80000000,0x1b000000,0x36000000,0x6c000000,0xd8000000,
	                  0xab000000,0x4d000000,0x9a000000};

	switch (keysize) {
		case 128: Nr = 10; Nk = 4; break;
		case 192: Nr = 12; Nk = 6; break;
		case 256: Nr = 14; Nk = 8; break;
		default: return;
	}

	for (idx=0; idx < Nk; ++idx) {
		w[idx] = ((key[4 * idx]) << 24) | ((key[4 * idx + 1]) << 16) |
				   ((key[4 * idx + 2]) << 8) | ((key[4 * idx + 3]));
	}

	for (idx = Nk; idx < Nb * (Nr+1); ++idx) {
		temp = w[idx - 1];
		if ((idx % Nk) == 0)
			temp = SubWord(KE_ROTWORD(temp)) ^ Rcon[(idx-1)/Nk];
		else if (Nk > 6 && (idx % Nk) == 4)
			temp = SubWord(temp);
		w[idx] = w[idx-Nk] ^ temp;
	}
}

/////////////////
// ADD ROUND KEY
/////////////////

// Performs the AddRoundKey step. Each round has its own pre-generated 16-byte key in the
// form of 4 integers (the "w" array). Each integer is XOR'd by one column of the state.
// Also performs the job of InvAddRoundKey(); since the function is a simple XOR process,
// it is its own inverse.
void AddRoundKey(BYTE state[][4], const WORD w[])
{
	BYTE subkey[4];

	// memcpy(subkey,&w[idx],4); // Not accurate for big endian machines
	// Subkey 1
	subkey[0] = w[0] >> 24;
	subkey[1] = w[0] >> 16;
	subkey[2] = w[0] >> 8;
	subkey[3] = w[0];
	state[0][0] ^= subkey[0];
	state[1][0] ^= subkey[1];
	state[2][0] ^= subkey[2];
	state[3][0] ^= subkey[3];
	// Subkey 2
	subkey[0] = w[1] >> 24;
	subkey[1] = w[1] >> 16;
	subkey[2] = w[1] >> 8;
	subkey[3] = w[1];
	state[0][1] ^= subkey[0];
	state[1][1] ^= subkey[1];
	state[2][1] ^= subkey[2];
	state[3][1] ^= subkey[3];
	// Subkey 3
	subkey[0] = w[2] >> 24;
	subkey[1] = w[2] >> 16;
	subkey[2] = w[2] >> 8;
	subkey[3] = w[2];
	state[0][2] ^= subkey[0];
	state[1][2] ^= subkey[1];
	state[2][2] ^= subkey[2];
	state[3][2] ^= subkey[3];
	// Subkey 4
	subkey[0] = w[3] >> 24;
	subkey[1] = w[3] >> 16;
	subkey[2] = w[3] >> 8;
	subkey[3] = w[3];
	state[0][3] ^= subkey[0];
	state[1][3] ^= subkey[1];
	state[2][3] ^= subkey[2];
	state[3][3] ^= subkey[3];
}

/////////////////
// (Inv)SubBytes
/////////////////

// Performs the SubBytes step. All bytes in the state are substituted with a
// pre-calculated value from a lookup table.
void SubBytes(BYTE state[][4])
{
	state[0][0] = aes_sbox[state[0][0] >> 4][state[0][0] & 0x0F];
	state[0][1] = aes_sbox[state[0][1] >> 4][state[0][1] & 0x0F];
	state[0][2] = aes_sbox[state[0][2] >> 4][state[0][2] & 0x0F];
	state[0][3] = aes_sbox[state[0][3] >> 4][state[0][3] & 0x0F];
	state[1][0] = aes_sbox[state[1][0] >> 4][state[1][0] & 0x0F];
	state[1][1] = aes_sbox[state[1][1] >> 4][state[1][1] & 0x0F];
	state[1][2] = aes_sbox[state[1][2] >> 4][state[1][2] & 0x0F];
	state[1][3] = aes_sbox[state[1][3] >> 4][state[1][3] & 0x0F];
	state[2][0] = aes_sbox[state[2][0] >> 4][state[2][0] & 0x0F];
	state[2][1] = aes_sbox[state[2][1] >> 4][state[2][1] & 0x0F];
	state[2][2] = aes_sbox[state[2][2] >> 4][state[2][2] & 0x0F];
	state[2][3] = aes_sbox[state[2][3] >> 4][state[2][3] & 0x0F];
	state[3][0] = aes_sbox[state[3][0] >> 4][state[3][0] & 0x0F];
	state[3][1] = aes_sbox[state[3][1] >> 4][state[3][1] & 0x0F];
	state[3][2] = aes_sbox[state[3][2] >> 4][state[3][2] & 0x0F];
	state[3][3] = aes_sbox[state[3][3] >> 4][state[3][3] & 0x0F];
}

void InvSubBytes(BYTE state[][4])
{
	state[0][0] = aes_invsbox[state[0][0] >> 4][state[0][0] & 0x0F];
	state[0][1] = aes_invsbox[state[0][1] >> 4][state[0][1] & 0x0F];
	state[0][2] = aes_invsbox[state[0][2] >> 4][state[0][2] & 0x0F];
	state[0][3] = aes_invsbox[state[0][3] >> 4][state[0][3] & 0x0F];
	state[1][0] = aes_invsbox[state[1][0] >> 4][state[1][0] & 0x0F];
	state[1][1] = aes_invsbox[state[1][1] >> 4][state[1][1] & 0x0F];
	state[1][2] = aes_invsbox[state[1][2] >> 4][state[1][2] & 0x0F];
	state[1][3] = aes_invsbox[state[1][3] >> 4][state[1][3] & 0x0F];
	state[2][0] = aes_invsbox[state[2][0] >> 4][state[2][0] & 0x0F];
	state[2][1] = aes_invsbox[state[2][1] >> 4][state[2][1] & 0x0F];
	state[2][2] = aes_invsbox[state[2][2] >> 4][state[2][2] & 0x0F];
	state[2][3] = aes_invsbox[state[2][3] >> 4][state[2][3] & 0x0F];
	state[3][0] = aes_invsbox[state[3][0] >> 4][state[3][0] & 0x0F];
	state[3][1] = aes_invsbox[state[3][1] >> 4][state[3][1] & 0x0F];
	state[3][2] = aes_invsbox[state[3][2] >> 4][state[3][2] & 0x0F];
	state[3][3] = aes_invsbox[state[3][3] >> 4][state[3][3] & 0x0F];
}

/////////////////
// (Inv)ShiftRows
/////////////////

// Performs the ShiftRows step. All rows are shifted cylindrically to the left.
void ShiftRows(BYTE state[][4])
{
	int t;

	// Shift left by 1
	t = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = t;
	// Shift left by 2
	t = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = t;
	t = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = t;
	// Shift left by 3
	t = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = t;
}

// All rows are shifted cylindrically to the right.
void InvShiftRows(BYTE state[][4])
{
	int t;

	// Shift right by 1
	t = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = t;
	// Shift right by 2
	t = state[2][3];
	state[2][3] = state[2][1];
	state[2][1] = t;
	t = state[2][2];
	state[2][2] = state[2][0];
	state[2][0] = t;
	// Shift right by 3
	t = state[3][3];
	state[3][3] = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = t;
}

/////////////////
// (Inv)MixColumns
/////////////////

// Performs the MixColums step. The state is multiplied by itself using matrix
// multiplication in a Galios Field 2^8. All multiplication is pre-computed in a table.
// Addition is equivilent to XOR. (Must always make a copy of the column as the original
// values will be destoyed.)
void MixColumns(BYTE state[][4])
{
	BYTE col[4];

	// Column 1
	col[0] = state[0][0];
	col[1] = state[1][0];
	col[2] = state[2][0];
	col[3] = state[3][0];
	state[0][0] = gf_mul[col[0]][0];
	state[0][0] ^= gf_mul[col[1]][1];
	state[0][0] ^= col[2];
	state[0][0] ^= col[3];
	state[1][0] = col[0];
	state[1][0] ^= gf_mul[col[1]][0];
	state[1][0] ^= gf_mul[col[2]][1];
	state[1][0] ^= col[3];
	state[2][0] = col[0];
	state[2][0] ^= col[1];
	state[2][0] ^= gf_mul[col[2]][0];
	state[2][0] ^= gf_mul[col[3]][1];
	state[3][0] = gf_mul[col[0]][1];
	state[3][0] ^= col[1];
	state[3][0] ^= col[2];
	state[3][0] ^= gf_mul[col[3]][0];
	// Column 2
	col[0] = state[0][1];
	col[1] = state[1][1];
	col[2] = state[2][1];
	col[3] = state[3][1];
	state[0][1] = gf_mul[col[0]][0];
	state[0][1] ^= gf_mul[col[1]][1];
	state[0][1] ^= col[2];
	state[0][1] ^= col[3];
	state[1][1] = col[0];
	state[1][1] ^= gf_mul[col[1]][0];
	state[1][1] ^= gf_mul[col[2]][1];
	state[1][1] ^= col[3];
	state[2][1] = col[0];
	state[2][1] ^= col[1];
	state[2][1] ^= gf_mul[col[2]][0];
	state[2][1] ^= gf_mul[col[3]][1];
	state[3][1] = gf_mul[col[0]][1];
	state[3][1] ^= col[1];
	state[3][1] ^= col[2];
	state[3][1] ^= gf_mul[col[3]][0];
	// Column 3
	col[0] = state[0][2];
	col[1] = state[1][2];
	col[2] = state[2][2];
	col[3] = state[3][2];
	state[0][2] = gf_mul[col[0]][0];
	state[0][2] ^= gf_mul[col[1]][1];
	state[0][2] ^= col[2];
	state[0][2] ^= col[3];
	state[1][2] = col[0];
	state[1][2] ^= gf_mul[col[1]][0];
	state[1][2] ^= gf_mul[col[2]][1];
	state[1][2] ^= col[3];
	state[2][2] = col[0];
	state[2][2] ^= col[1];
	state[2][2] ^= gf_mul[col[2]][0];
	state[2][2] ^= gf_mul[col[3]][1];
	state[3][2] = gf_mul[col[0]][1];
	state[3][2] ^= col[1];
	state[3][2] ^= col[2];
	state[3][2] ^= gf_mul[col[3]][0];
	// Column 4
	col[0] = state[0][3];
	col[1] = state[1][3];
	col[2] = state[2][3];
	col[3] = state[3][3];
	state[0][3] = gf_mul[col[0]][0];
	state[0][3] ^= gf_mul[col[1]][1];
	state[0][3] ^= col[2];
	state[0][3] ^= col[3];
	state[1][3] = col[0];
	state[1][3] ^= gf_mul[col[1]][0];
	state[1][3] ^= gf_mul[col[2]][1];
	state[1][3] ^= col[3];
	state[2][3] = col[0];
	state[2][3] ^= col[1];
	state[2][3] ^= gf_mul[col[2]][0];
	state[2][3] ^= gf_mul[col[3]][1];
	state[3][3] = gf_mul[col[0]][1];
	state[3][3] ^= col[1];
	state[3][3] ^= col[2];
	state[3][3] ^= gf_mul[col[3]][0];
}

void InvMixColumns(BYTE state[][4])
{
	BYTE col[4];

	// Column 1
	col[0] = state[0][0];
	col[1] = state[1][0];
	col[2] = state[2][0];
	col[3] = state[3][0];
	state[0][0] = gf_mul[col[0]][5];
	state[0][0] ^= gf_mul[col[1]][3];
	state[0][0] ^= gf_mul[col[2]][4];
	state[0][0] ^= gf_mul[col[3]][2];
	state[1][0] = gf_mul[col[0]][2];
	state[1][0] ^= gf_mul[col[1]][5];
	state[1][0] ^= gf_mul[col[2]][3];
	state[1][0] ^= gf_mul[col[3]][4];
	state[2][0] = gf_mul[col[0]][4];
	state[2][0] ^= gf_mul[col[1]][2];
	state[2][0] ^= gf_mul[col[2]][5];
	state[2][0] ^= gf_mul[col[3]][3];
	state[3][0] = gf_mul[col[0]][3];
	state[3][0] ^= gf_mul[col[1]][4];
	state[3][0] ^= gf_mul[col[2]][2];
	state[3][0] ^= gf_mul[col[3]][5];
	// Column 2
	col[0] = state[0][1];
	col[1] = state[1][1];
	col[2] = state[2][1];
	col[3] = state[3][1];
	state[0][1] = gf_mul[col[0]][5];
	state[0][1] ^= gf_mul[col[1]][3];
	state[0][1] ^= gf_mul[col[2]][4];
	state[0][1] ^= gf_mul[col[3]][2];
	state[1][1] = gf_mul[col[0]][2];
	state[1][1] ^= gf_mul[col[1]][5];
	state[1][1] ^= gf_mul[col[2]][3];
	state[1][1] ^= gf_mul[col[3]][4];
	state[2][1] = gf_mul[col[0]][4];
	state[2][1] ^= gf_mul[col[1]][2];
	state[2][1] ^= gf_mul[col[2]][5];
	state[2][1] ^= gf_mul[col[3]][3];
	state[3][1] = gf_mul[col[0]][3];
	state[3][1] ^= gf_mul[col[1]][4];
	state[3][1] ^= gf_mul[col[2]][2];
	state[3][1] ^= gf_mul[col[3]][5];
	// Column 3
	col[0] = state[0][2];
	col[1] = state[1][2];
	col[2] = state[2][2];
	col[3] = state[3][2];
	state[0][2] = gf_mul[col[0]][5];
	state[0][2] ^= gf_mul[col[1]][3];
	state[0][2] ^= gf_mul[col[2]][4];
	state[0][2] ^= gf_mul[col[3]][2];
	state[1][2] = gf_mul[col[0]][2];
	state[1][2] ^= gf_mul[col[1]][5];
	state[1][2] ^= gf_mul[col[2]][3];
	state[1][2] ^= gf_mul[col[3]][4];
	state[2][2] = gf_mul[col[0]][4];
	state[2][2] ^= gf_mul[col[1]][2];
	state[2][2] ^= gf_mul[col[2]][5];
	state[2][2] ^= gf_mul[col[3]][3];
	state[3][2] = gf_mul[col[0]][3];
	state[3][2] ^= gf_mul[col[1]][4];
	state[3][2] ^= gf_mul[col[2]][2];
	state[3][2] ^= gf_mul[col[3]][5];
	// Column 4
	col[0] = state[0][3];
	col[1] = state[1][3];
	col[2] = state[2][3];
	col[3] = state[3][3];
	state[0][3] = gf_mul[col[0]][5];
	state[0][3] ^= gf_mul[col[1]][3];
	state[0][3] ^= gf_mul[col[2]][4];
	state[0][3] ^= gf_mul[col[3]][2];
	state[1][3] = gf_mul[col[0]][2];
	state[1][3] ^= gf_mul[col[1]][5];
	state[1][3] ^= gf_mul[col[2]][3];
	state[1][3] ^= gf_mul[col[3]][4];
	state[2][3] = gf_mul[col[0]][4];
	state[2][3] ^= gf_mul[col[1]][2];
	state[2][3] ^= gf_mul[col[2]][5];
	state[2][3] ^= gf_mul[col[3]][3];
	state[3][3] = gf_mul[col[0]][3];
	state[3][3] ^= gf_mul[col[1]][4];
	state[3][3] ^= gf_mul[col[2]][2];
	state[3][3] ^= gf_mul[col[3]][5];
}

/////////////////
// (En/De)Crypt
/////////////////

void aes_encrypt(const BYTE in[], BYTE out[], const WORD key[], int keysize)
{
	BYTE state[4][4];

	// Copy input array (should be 16 bytes long) to a matrix (sequential bytes are ordered
	// by row, not col) called "state" for processing.
	// *** Implementation note: The official AES documentation references the state by
	// column, then row. Accessing an element in C requires row then column. Thus, all state
	// references in AES must have the column and row indexes reversed for C implementation.
	state[0][0] = in[0];
	state[1][0] = in[1];
	state[2][0] = in[2];
	state[3][0] = in[3];
	state[0][1] = in[4];
	state[1][1] = in[5];
	state[2][1] = in[6];
	state[3][1] = in[7];
	state[0][2] = in[8];
	state[1][2] = in[9];
	state[2][2] = in[10];
	state[3][2] = in[11];
	state[0][3] = in[12];
	state[1][3] = in[13];
	state[2][3] = in[14];
	state[3][3] = in[15];

	// Perform the necessary number of rounds. The round key is added first.
	// The last round does not perform the MixColumns step.
	AddRoundKey(state,&key[0]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[4]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[8]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[12]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[16]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[20]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[24]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[28]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[32]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[36]);
	if (keysize != 128) {
		SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[40]);
		SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[44]);
		if (keysize != 192) {
			SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[48]);
			SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[52]);
			SubBytes(state); ShiftRows(state); AddRoundKey(state,&key[56]);
		}
		else {
			SubBytes(state); ShiftRows(state); AddRoundKey(state,&key[48]);
		}
	}
	else {
		SubBytes(state); ShiftRows(state); AddRoundKey(state,&key[40]);
	}

	// Copy the state to the output array.
	out[0] = state[0][0];
	out[1] = state[1][0];
	out[2] = state[2][0];
	out[3] = state[3][0];
	out[4] = state[0][1];
	out[5] = state[1][1];
	out[6] = state[2][1];
	out[7] = state[3][1];
	out[8] = state[0][2];
	out[9] = state[1][2];
	out[10] = state[2][2];
	out[11] = state[3][2];
	out[12] = state[0][3];
	out[13] = state[1][3];
	out[14] = state[2][3];
	out[15] = state[3][3];
}

void aes_decrypt(const BYTE in[], BYTE out[], const WORD key[], int keysize)
{
	BYTE state[4][4];

	// Copy the input to the state.
	state[0][0] = in[0];
	state[1][0] = in[1];
	state[2][0] = in[2];
	state[3][0] = in[3];
	state[0][1] = in[4];
	state[1][1] = in[5];
	state[2][1] = in[6];
	state[3][1] = in[7];
	state[0][2] = in[8];
	state[1][2] = in[9];
	state[2][2] = in[10];
	state[3][2] = in[11];
	state[0][3] = in[12];
	state[1][3] = in[13];
	state[2][3] = in[14];
	state[3][3] = in[15];

	// Perform the necessary number of rounds. The round key is added first.
	// The last round does not perform the MixColumns step.
	if (keysize > 128) {
		if (keysize > 192) {
			AddRoundKey(state,&key[56]);
			InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[52]);InvMixColumns(state);
			InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[48]);InvMixColumns(state);
		}
		else {
			AddRoundKey(state,&key[48]);
		}
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[44]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[40]);InvMixColumns(state);
	}
	else {
		AddRoundKey(state,&key[40]);
	}
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[36]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[32]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[28]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[24]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[20]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[16]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[12]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[8]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[4]);InvMixColumns(state);
	InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[0]);

	// Copy the state to the output array.
	out[0] = state[0][0];
	out[1] = state[1][0];
	out[2] = state[2][0];
	out[3] = state[3][0];
	out[4] = state[0][1];
	out[5] = state[1][1];
	out[6] = state[2][1];
	out[7] = state[3][1];
	out[8] = state[0][2];
	out[9] = state[1][2];
	out[10] = state[2][2];
	out[11] = state[3][2];
	out[12] = state[0][3];
	out[13] = state[1][3];
	out[14] = state[2][3];
	out[15] = state[3][3];
}

/*******************
** AES DEBUGGING FUNCTIONS
*******************/
/*
// This prints the "state" grid as a linear hex string.
void print_state(BYTE state[][4])
{
	int idx,idx2;
	for (idx=0; idx < 4; idx++)
		for (idx2=0; idx2 < 4; idx2++)
			printf("%02x",state[idx2][idx]);
	printf("\n");
}
// This prints the key (4 consecutive ints) used for a given round as a linear hex string.
void print_rnd_key(WORD key[])
{
	int idx;
	for (idx=0; idx < 4; idx++)
		printf("%08x",key[idx]);
	printf("\n");
}
*/
/********************/


/*********************** FUNCTION DEFINITIONS ***********************/
void print_hex(BYTE str[], int len)
{
	int idx;

	for(idx = 0; idx < len; idx++)
		printf("%02x", str[idx]);
}

int aes_ecb_test()
{
	WORD key_schedule[60], idx;
	BYTE enc_buf[128];
	BYTE plaintext[2][16] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
		{0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[2][16] = {
		{0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8},
		{0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70}
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	// Raw ECB mode.
	//printf("* ECB mode:\n");
	aes_key_setup(key[0], key_schedule, 256);
	//printf(  "Key          : ");
	//print_hex(key[0], 32);

	for(idx = 0; idx < 2; idx++) {
		aes_encrypt(plaintext[idx], enc_buf, key_schedule, 256);
		//printf("\nPlaintext    : ");
		//print_hex(plaintext[idx], 16);
		//printf("\n-encrypted to: ");
		//print_hex(enc_buf, 16);
		pass = pass && !memcmp(enc_buf, ciphertext[idx], 16);

		aes_decrypt(ciphertext[idx], enc_buf, key_schedule, 256);
		//printf("\nCiphertext   : ");
		//print_hex(ciphertext[idx], 16);
		//printf("\n-decrypted to: ");
		//print_hex(enc_buf, 16);
		pass = pass && !memcmp(enc_buf, plaintext[idx], 16);

		//printf("\n\n");
	}

	return(pass);
}

int aes_cbc_test()
{
	WORD key_schedule[60];
	BYTE enc_buf[128];
	BYTE plaintext[1][32] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[1][32] = {
		{0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d}
	};
	BYTE iv[1][16] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	//printf("* CBC mode:\n");
	aes_key_setup(key[0], key_schedule, 256);

	//printf(  "Key          : ");
	//print_hex(key[0], 32);
	//printf("\nIV           : ");
	//print_hex(iv[0], 16);

	aes_encrypt_cbc(plaintext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	//printf("\nPlaintext    : ");
	//print_hex(plaintext[0], 32);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, 32);
	//printf("\nCiphertext   : ");
	//print_hex(ciphertext[0], 32);
	pass = pass && !memcmp(enc_buf, ciphertext[0], 32);

	aes_decrypt_cbc(ciphertext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	//printf("\nCiphertext   : ");
	//print_hex(ciphertext[0], 32);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, 32);
	//printf("\nPlaintext   : ");
	//print_hex(plaintext[0], 32);
	pass = pass && !memcmp(enc_buf, plaintext[0], 32);

	//printf("\n\n");
	return(pass);
}

int aes_ctr_test()
{
	WORD key_schedule[60];
	BYTE enc_buf[128];
	BYTE plaintext[1][32] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[1][32] = {
		{0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5}
	};
	BYTE iv[1][16] = {
		{0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff},
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	//printf("* CTR mode:\n");
	aes_key_setup(key[0], key_schedule, 256);

	//printf(  "Key          : ");
	//print_hex(key[0], 32);
	//printf("\nIV           : ");
	//print_hex(iv[0], 16);

	aes_encrypt_ctr(plaintext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	//printf("\nPlaintext    : ");
	//print_hex(plaintext[0], 32);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, 32);
	pass = pass && !memcmp(enc_buf, ciphertext[0], 32);

	aes_decrypt_ctr(ciphertext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	//printf("\nCiphertext   : ");
	//print_hex(ciphertext[0], 32);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, 32);
	pass = pass && !memcmp(enc_buf, plaintext[0], 32);

	//printf("\n\n");
	return(pass);
}

int aes_ccm_test()
{
	int mac_auth;
	WORD enc_buf_len;
	BYTE enc_buf[128];
	BYTE plaintext[3][32] = {
		{0x20,0x21,0x22,0x23},
		{0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f},
		{0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}
	};
	BYTE assoc[3][32] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07},
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13}
	};
	BYTE ciphertext[3][32 + 16] = {
		{0x71,0x62,0x01,0x5b,0x4d,0xac,0x25,0x5d},
		{0xd2,0xa1,0xf0,0xe0,0x51,0xea,0x5f,0x62,0x08,0x1a,0x77,0x92,0x07,0x3d,0x59,0x3d,0x1f,0xc6,0x4f,0xbf,0xac,0xcd},
		{0xe3,0xb2,0x01,0xa9,0xf5,0xb7,0x1a,0x7a,0x9b,0x1c,0xea,0xec,0xcd,0x97,0xe7,0x0b,0x61,0x76,0xaa,0xd9,0xa4,0x42,0x8a,0xa5,0x48,0x43,0x92,0xfb,0xc1,0xb0,0x99,0x51}
	};
	BYTE iv[3][16] = {
		{0x10,0x11,0x12,0x13,0x14,0x15,0x16},
		{0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17},
		{0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b}
	};
	BYTE key[1][32] = {
		{0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f}
	};
	int pass = 1;

	//printf("* CCM mode:\n");
	//printf("Key           : ");
	//print_hex(key[0], 16);

	//print_hex(plaintext[0], 4);
	//print_hex(assoc[0], 8);
	//print_hex(ciphertext[0], 8);
	//print_hex(iv[0], 7);
	//print_hex(key[0], 16);

	aes_encrypt_ccm(plaintext[0], 4, assoc[0], 8, iv[0], 7, enc_buf, &enc_buf_len, 4, key[0], 128);
	//printf("\nNONCE        : ");
	//print_hex(iv[0], 7);
	//printf("\nAssoc. Data  : ");
	//print_hex(assoc[0], 8);
	//printf("\nPayload       : ");
	//print_hex(plaintext[0], 4);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	pass = pass && !memcmp(enc_buf, ciphertext[0], enc_buf_len);

	aes_decrypt_ccm(ciphertext[0], 8, assoc[0], 8, iv[0], 7, enc_buf, &enc_buf_len, 4, &mac_auth, key[0], 128);
	//printf("\n-Ciphertext  : ");
	//print_hex(ciphertext[0], 8);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	//printf("\nAuthenticated: %d ", mac_auth);
	pass = pass && !memcmp(enc_buf, plaintext[0], enc_buf_len) && mac_auth;


	aes_encrypt_ccm(plaintext[1], 16, assoc[1], 16, iv[1], 8, enc_buf, &enc_buf_len, 6, key[0], 128);
	//printf("\n\nNONCE        : ");
	//print_hex(iv[1], 8);
	//printf("\nAssoc. Data  : ");
	//print_hex(assoc[1], 16);
	//printf("\nPayload      : ");
	//print_hex(plaintext[1], 16);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	pass = pass && !memcmp(enc_buf, ciphertext[1], enc_buf_len);

	aes_decrypt_ccm(ciphertext[1], 22, assoc[1], 16, iv[1], 8, enc_buf, &enc_buf_len, 6, &mac_auth, key[0], 128);
	//printf("\n-Ciphertext  : ");
	//print_hex(ciphertext[1], 22);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	//printf("\nAuthenticated: %d ", mac_auth);
	pass = pass && !memcmp(enc_buf, plaintext[1], enc_buf_len) && mac_auth;


	aes_encrypt_ccm(plaintext[2], 24, assoc[2], 20, iv[2], 12, enc_buf, &enc_buf_len, 8, key[0], 128);
	//printf("\n\nNONCE        : ");
	//print_hex(iv[2], 12);
	//printf("\nAssoc. Data  : ");
	//print_hex(assoc[2], 20);
	//printf("\nPayload      : ");
	//print_hex(plaintext[2], 24);
	//printf("\n-encrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	pass = pass && !memcmp(enc_buf, ciphertext[2], enc_buf_len);

	aes_decrypt_ccm(ciphertext[2], 32, assoc[2], 20, iv[2], 12, enc_buf, &enc_buf_len, 8, &mac_auth, key[0], 128);
	//printf("\n-Ciphertext  : ");
	//print_hex(ciphertext[2], 32);
	//printf("\n-decrypted to: ");
	//print_hex(enc_buf, enc_buf_len);
	//printf("\nAuthenticated: %d ", mac_auth);
	pass = pass && !memcmp(enc_buf, plaintext[2], enc_buf_len) && mac_auth;

	//printf("\n\n");
	return(pass);
}
#include<time.h>
int aes_test()
{
    clock_t st1,end1;
    double tm1 ;
	int pass = 1,loop;

    st1 = clock();
     for(loop=0; loop<=8200; loop++)
        {
          aes_ecb_test();
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By AES ECB Test is %f seconds",tm1);

    st1 = clock();
     for(loop=0; loop<=8200; loop++)
        {
          aes_cbc_test();
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By AES CBC Test is %f seconds",tm1);


     st1 = clock();
     for(loop=0; loop<=8200; loop++)
        {
          aes_ctr_test();
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By AES CTR Test is %f seconds",tm1);

    st1 = clock();
     for(loop=0; loop<=8200; loop++)
        {
          aes_ccm_test();
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By AES CCM Test is %f seconds",tm1);

     st1 = clock();
     for(loop=0; loop<=8200; loop++)
        {
          rc4_test();
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By ARC 4 Test is %f seconds",tm1);



     /*
	pass = pass && aes_ecb_test();
	pass = pass && aes_cbc_test();
	pass = pass && aes_ctr_test();
	pass = pass && aes_ccm_test();
     */
	return(pass);
}

void arcfour_key_setup(BYTE state[], const BYTE key[], int len)
{
	int i, j;
	BYTE t;

	for (i = 0; i < 256; ++i)
		state[i] = i;
	for (i = 0, j = 0; i < 256; ++i) {
		j = (j + state[i] + key[i % len]) % 256;
		t = state[i];
		state[i] = state[j];
		state[j] = t;
	}
}

// This does not hold state between calls. It always generates the
// stream starting from the first  output byte.
void arcfour_generate_stream(BYTE state[], BYTE out[], size_t len)
{
	int i, j;
	size_t idx;
	BYTE t;

	for (idx = 0, i = 0, j = 0; idx < len; ++idx)  {
		i = (i + 1) % 256;
		j = (j + state[i]) % 256;
		t = state[i];
		state[i] = state[j];
		state[j] = t;
		out[idx] = state[(state[i] + state[j]) % 256];
	}
}

int rc4_test()
{
	BYTE state[256];
	BYTE key[3][10] = {{"Key"}, {"Wiki"}, {"Secret"}};
	BYTE stream[3][10] = {{0xEB,0x9F,0x77,0x81,0xB7,0x34,0xCA,0x72,0xA7,0x19},
	                      {0x60,0x44,0xdb,0x6d,0x41,0xb7},
	                      {0x04,0xd4,0x6b,0x05,0x3c,0xa8,0x7b,0x59}};
	int stream_len[3] = {10,6,8};
	BYTE buf[1024];
	int idx;
	int pass = 1;

	// Only test the output stream. Note that the state can be reused.
	for (idx = 0; idx < 3; idx++) {
		arcfour_key_setup(state, key[idx], strlen(key[idx]));
		arcfour_generate_stream(state, buf, stream_len[idx]);
		pass = pass && !memcmp(stream[idx], buf, stream_len[idx]);
	}

	return(pass);
}

int blowfish_test()
{
	BYTE key1[8]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	BYTE key2[8]  = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
	BYTE key3[24] = {0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,
	                 0x78,0x69,0x5A,0x4B,0x3C,0x2D,0x1E,0x0F,
	                 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
	BYTE p1[BLOWFISH_BLOCK_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	BYTE p2[BLOWFISH_BLOCK_SIZE] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
	BYTE p3[BLOWFISH_BLOCK_SIZE] = {0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};

	BYTE c1[BLOWFISH_BLOCK_SIZE] = {0x4e,0xf9,0x97,0x45,0x61,0x98,0xdd,0x78};
	BYTE c2[BLOWFISH_BLOCK_SIZE] = {0x51,0x86,0x6f,0xd5,0xb8,0x5e,0xcb,0x8a};
	BYTE c3[BLOWFISH_BLOCK_SIZE] = {0x05,0x04,0x4b,0x62,0xfa,0x52,0xd0,0x80};

	BYTE enc_buf[BLOWFISH_BLOCK_SIZE];
	BLOWFISH_KEY key;
	int pass = 1;

	// Test vector 1.
	blowfish_key_setup(key1, &key, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt(p1, enc_buf, &key);
	pass = pass && !memcmp(c1, enc_buf, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt(c1, enc_buf, &key);
	pass = pass && !memcmp(p1, enc_buf, BLOWFISH_BLOCK_SIZE);

	// Test vector 2.
	blowfish_key_setup(key2, &key, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt(p2, enc_buf, &key);
	pass = pass && !memcmp(c2, enc_buf, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt(c2, enc_buf, &key);
	pass = pass && !memcmp(p2, enc_buf, BLOWFISH_BLOCK_SIZE);

	// Test vector 3.
	blowfish_key_setup(key3, &key, 24);
	blowfish_encrypt(p3, enc_buf, &key);
	pass = pass && !memcmp(c3, enc_buf, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt(c3, enc_buf, &key);
	pass = pass && !memcmp(p3, enc_buf, BLOWFISH_BLOCK_SIZE);

	return(pass);
}

/* DES remaining Code Begins */

/****************************** MACROS ******************************/
// Obtain bit "b" from the left and shift it "c" places from the right
#define BITNUM(a,b,c) (((a[(b)/8] >> (7 - (b%8))) & 0x01) << (c))
#define BITNUMINTR(a,b,c) ((((a) >> (31 - (b))) & 0x00000001) << (c))
#define BITNUMINTL(a,b,c) ((((a) << (b)) & 0x80000000) >> (c))

// This macro converts a 6 bit block with the S-Box row defined as the first and last
// bits to a 6 bit block with the row defined by the first two bits.
#define SBOXBIT(a) (((a) & 0x20) | (((a) & 0x1f) >> 1) | (((a) & 0x01) << 4))

/**************************** VARIABLES *****************************/
static const BYTE sbox1[64] = {
	14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7,
	 0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8,
	 4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0,
	15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13
};
static const BYTE sbox2[64] = {
	15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10,
	 3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5,
	 0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15,
	13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9
};
static const BYTE sbox3[64] = {
	10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8,
	13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1,
	13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7,
	 1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12
};
static const BYTE sbox4[64] = {
	 7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15,
	13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9,
	10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4,
	 3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14
};
static const BYTE sbox5[64] = {
	 2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9,
	14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6,
	 4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14,
	11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3
};
static const BYTE sbox6[64] = {
	12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11,
	10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8,
	 9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6,
	 4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13
};
static const BYTE sbox7[64] = {
	 4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1,
	13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6,
	 1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2,
	 6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12
};
static const BYTE sbox8[64] = {
	13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7,
	 1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2,
	 7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8,
	 2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11
};

/*********************** FUNCTION DEFINITIONS ***********************/
// Initial (Inv)Permutation step
void IP(WORD state[], const BYTE in[])
{
	state[0] = BITNUM(in,57,31) | BITNUM(in,49,30) | BITNUM(in,41,29) | BITNUM(in,33,28) |
				  BITNUM(in,25,27) | BITNUM(in,17,26) | BITNUM(in,9,25) | BITNUM(in,1,24) |
				  BITNUM(in,59,23) | BITNUM(in,51,22) | BITNUM(in,43,21) | BITNUM(in,35,20) |
				  BITNUM(in,27,19) | BITNUM(in,19,18) | BITNUM(in,11,17) | BITNUM(in,3,16) |
				  BITNUM(in,61,15) | BITNUM(in,53,14) | BITNUM(in,45,13) | BITNUM(in,37,12) |
				  BITNUM(in,29,11) | BITNUM(in,21,10) | BITNUM(in,13,9) | BITNUM(in,5,8) |
				  BITNUM(in,63,7) | BITNUM(in,55,6) | BITNUM(in,47,5) | BITNUM(in,39,4) |
				  BITNUM(in,31,3) | BITNUM(in,23,2) | BITNUM(in,15,1) | BITNUM(in,7,0);

	state[1] = BITNUM(in,56,31) | BITNUM(in,48,30) | BITNUM(in,40,29) | BITNUM(in,32,28) |
				  BITNUM(in,24,27) | BITNUM(in,16,26) | BITNUM(in,8,25) | BITNUM(in,0,24) |
				  BITNUM(in,58,23) | BITNUM(in,50,22) | BITNUM(in,42,21) | BITNUM(in,34,20) |
				  BITNUM(in,26,19) | BITNUM(in,18,18) | BITNUM(in,10,17) | BITNUM(in,2,16) |
				  BITNUM(in,60,15) | BITNUM(in,52,14) | BITNUM(in,44,13) | BITNUM(in,36,12) |
				  BITNUM(in,28,11) | BITNUM(in,20,10) | BITNUM(in,12,9) | BITNUM(in,4,8) |
				  BITNUM(in,62,7) | BITNUM(in,54,6) | BITNUM(in,46,5) | BITNUM(in,38,4) |
				  BITNUM(in,30,3) | BITNUM(in,22,2) | BITNUM(in,14,1) | BITNUM(in,6,0);
}

void InvIP(WORD state[], BYTE in[])
{
	in[0] = BITNUMINTR(state[1],7,7) | BITNUMINTR(state[0],7,6) | BITNUMINTR(state[1],15,5) |
			  BITNUMINTR(state[0],15,4) | BITNUMINTR(state[1],23,3) | BITNUMINTR(state[0],23,2) |
			  BITNUMINTR(state[1],31,1) | BITNUMINTR(state[0],31,0);

	in[1] = BITNUMINTR(state[1],6,7) | BITNUMINTR(state[0],6,6) | BITNUMINTR(state[1],14,5) |
			  BITNUMINTR(state[0],14,4) | BITNUMINTR(state[1],22,3) | BITNUMINTR(state[0],22,2) |
			  BITNUMINTR(state[1],30,1) | BITNUMINTR(state[0],30,0);

	in[2] = BITNUMINTR(state[1],5,7) | BITNUMINTR(state[0],5,6) | BITNUMINTR(state[1],13,5) |
			  BITNUMINTR(state[0],13,4) | BITNUMINTR(state[1],21,3) | BITNUMINTR(state[0],21,2) |
			  BITNUMINTR(state[1],29,1) | BITNUMINTR(state[0],29,0);

	in[3] = BITNUMINTR(state[1],4,7) | BITNUMINTR(state[0],4,6) | BITNUMINTR(state[1],12,5) |
			  BITNUMINTR(state[0],12,4) | BITNUMINTR(state[1],20,3) | BITNUMINTR(state[0],20,2) |
			  BITNUMINTR(state[1],28,1) | BITNUMINTR(state[0],28,0);

	in[4] = BITNUMINTR(state[1],3,7) | BITNUMINTR(state[0],3,6) | BITNUMINTR(state[1],11,5) |
			  BITNUMINTR(state[0],11,4) | BITNUMINTR(state[1],19,3) | BITNUMINTR(state[0],19,2) |
			  BITNUMINTR(state[1],27,1) | BITNUMINTR(state[0],27,0);

	in[5] = BITNUMINTR(state[1],2,7) | BITNUMINTR(state[0],2,6) | BITNUMINTR(state[1],10,5) |
			  BITNUMINTR(state[0],10,4) | BITNUMINTR(state[1],18,3) | BITNUMINTR(state[0],18,2) |
			  BITNUMINTR(state[1],26,1) | BITNUMINTR(state[0],26,0);

	in[6] = BITNUMINTR(state[1],1,7) | BITNUMINTR(state[0],1,6) | BITNUMINTR(state[1],9,5) |
			  BITNUMINTR(state[0],9,4) | BITNUMINTR(state[1],17,3) | BITNUMINTR(state[0],17,2) |
			  BITNUMINTR(state[1],25,1) | BITNUMINTR(state[0],25,0);

	in[7] = BITNUMINTR(state[1],0,7) | BITNUMINTR(state[0],0,6) | BITNUMINTR(state[1],8,5) |
			  BITNUMINTR(state[0],8,4) | BITNUMINTR(state[1],16,3) | BITNUMINTR(state[0],16,2) |
			  BITNUMINTR(state[1],24,1) | BITNUMINTR(state[0],24,0);
}

WORD f(WORD state, const BYTE key[])
{
	BYTE lrgstate[6]; //,i;
	WORD t1,t2;

	// Expantion Permutation
	t1 = BITNUMINTL(state,31,0) | ((state & 0xf0000000) >> 1) | BITNUMINTL(state,4,5) |
		  BITNUMINTL(state,3,6) | ((state & 0x0f000000) >> 3) | BITNUMINTL(state,8,11) |
		  BITNUMINTL(state,7,12) | ((state & 0x00f00000) >> 5) | BITNUMINTL(state,12,17) |
		  BITNUMINTL(state,11,18) | ((state & 0x000f0000) >> 7) | BITNUMINTL(state,16,23);

	t2 = BITNUMINTL(state,15,0) | ((state & 0x0000f000) << 15) | BITNUMINTL(state,20,5) |
		  BITNUMINTL(state,19,6) | ((state & 0x00000f00) << 13) | BITNUMINTL(state,24,11) |
		  BITNUMINTL(state,23,12) | ((state & 0x000000f0) << 11) | BITNUMINTL(state,28,17) |
		  BITNUMINTL(state,27,18) | ((state & 0x0000000f) << 9) | BITNUMINTL(state,0,23);

	lrgstate[0] = (t1 >> 24) & 0x000000ff;
	lrgstate[1] = (t1 >> 16) & 0x000000ff;
	lrgstate[2] = (t1 >> 8) & 0x000000ff;
	lrgstate[3] = (t2 >> 24) & 0x000000ff;
	lrgstate[4] = (t2 >> 16) & 0x000000ff;
	lrgstate[5] = (t2 >> 8) & 0x000000ff;

	// Key XOR
	lrgstate[0] ^= key[0];
	lrgstate[1] ^= key[1];
	lrgstate[2] ^= key[2];
	lrgstate[3] ^= key[3];
	lrgstate[4] ^= key[4];
	lrgstate[5] ^= key[5];

	// S-Box Permutation
	state = (sbox1[SBOXBIT(lrgstate[0] >> 2)] << 28) |
			  (sbox2[SBOXBIT(((lrgstate[0] & 0x03) << 4) | (lrgstate[1] >> 4))] << 24) |
			  (sbox3[SBOXBIT(((lrgstate[1] & 0x0f) << 2) | (lrgstate[2] >> 6))] << 20) |
			  (sbox4[SBOXBIT(lrgstate[2] & 0x3f)] << 16) |
			  (sbox5[SBOXBIT(lrgstate[3] >> 2)] << 12) |
			  (sbox6[SBOXBIT(((lrgstate[3] & 0x03) << 4) | (lrgstate[4] >> 4))] << 8) |
			  (sbox7[SBOXBIT(((lrgstate[4] & 0x0f) << 2) | (lrgstate[5] >> 6))] << 4) |
				sbox8[SBOXBIT(lrgstate[5] & 0x3f)];

	// P-Box Permutation
	state = BITNUMINTL(state,15,0) | BITNUMINTL(state,6,1) | BITNUMINTL(state,19,2) |
			  BITNUMINTL(state,20,3) | BITNUMINTL(state,28,4) | BITNUMINTL(state,11,5) |
			  BITNUMINTL(state,27,6) | BITNUMINTL(state,16,7) | BITNUMINTL(state,0,8) |
			  BITNUMINTL(state,14,9) | BITNUMINTL(state,22,10) | BITNUMINTL(state,25,11) |
			  BITNUMINTL(state,4,12) | BITNUMINTL(state,17,13) | BITNUMINTL(state,30,14) |
			  BITNUMINTL(state,9,15) | BITNUMINTL(state,1,16) | BITNUMINTL(state,7,17) |
			  BITNUMINTL(state,23,18) | BITNUMINTL(state,13,19) | BITNUMINTL(state,31,20) |
			  BITNUMINTL(state,26,21) | BITNUMINTL(state,2,22) | BITNUMINTL(state,8,23) |
			  BITNUMINTL(state,18,24) | BITNUMINTL(state,12,25) | BITNUMINTL(state,29,26) |
			  BITNUMINTL(state,5,27) | BITNUMINTL(state,21,28) | BITNUMINTL(state,10,29) |
			  BITNUMINTL(state,3,30) | BITNUMINTL(state,24,31);

	// Return the final state value
	return(state);
}

void des_key_setup(const BYTE key[], BYTE schedule[][6], DES_MODE mode)
{
	WORD i, j, to_gen, C, D;
	const WORD key_rnd_shift[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	const WORD key_perm_c[28] = {56,48,40,32,24,16,8,0,57,49,41,33,25,17,
	                             9,1,58,50,42,34,26,18,10,2,59,51,43,35};
	const WORD key_perm_d[28] = {62,54,46,38,30,22,14,6,61,53,45,37,29,21,
	                             13,5,60,52,44,36,28,20,12,4,27,19,11,3};
	const WORD key_compression[48] = {13,16,10,23,0,4,2,27,14,5,20,9,
	                                  22,18,11,3,25,7,15,6,26,19,12,1,
	                                  40,51,30,36,46,54,29,39,50,44,32,47,
	                                  43,48,38,55,33,52,45,41,49,35,28,31};

	// Permutated Choice #1 (copy the key in, ignoring parity bits).
	for (i = 0, j = 31, C = 0; i < 28; ++i, --j)
		C |= BITNUM(key,key_perm_c[i],j);
	for (i = 0, j = 31, D = 0; i < 28; ++i, --j)
		D |= BITNUM(key,key_perm_d[i],j);

	// Generate the 16 subkeys.
	for (i = 0; i < 16; ++i) {
		C = ((C << key_rnd_shift[i]) | (C >> (28-key_rnd_shift[i]))) & 0xfffffff0;
		D = ((D << key_rnd_shift[i]) | (D >> (28-key_rnd_shift[i]))) & 0xfffffff0;

		// Decryption subkeys are reverse order of encryption subkeys so
		// generate them in reverse if the key schedule is for decryption useage.
		if (mode == DES_DECRYPT)
			to_gen = 15 - i;
		else /*(if mode == DES_ENCRYPT)*/
			to_gen = i;
		// Initialize the array
		for (j = 0; j < 6; ++j)
			schedule[to_gen][j] = 0;
		for (j = 0; j < 24; ++j)
			schedule[to_gen][j/8] |= BITNUMINTR(C,key_compression[j],7 - (j%8));
		for ( ; j < 48; ++j)
			schedule[to_gen][j/8] |= BITNUMINTR(D,key_compression[j] - 28,7 - (j%8));
	}
}

void des_crypt(const BYTE in[], BYTE out[], const BYTE key[][6])
{
	WORD state[2],idx,t;

	IP(state,in);

	for (idx=0; idx < 15; ++idx) {
		t = state[1];
		state[1] = f(state[1],key[idx]) ^ state[0];
		state[0] = t;
	}
	// Perform the final loop manually as it doesn't switch sides
	state[0] = f(state[1],key[15]) ^ state[0];

	InvIP(state,out);
}

void three_des_key_setup(const BYTE key[], BYTE schedule[][16][6], DES_MODE mode)
{
	if (mode == DES_ENCRYPT) {
		des_key_setup(&key[0],schedule[0],mode);
		des_key_setup(&key[8],schedule[1],!mode);
		des_key_setup(&key[16],schedule[2],mode);
	}
	else /*if (mode == DES_DECRYPT*/ {
		des_key_setup(&key[16],schedule[0],mode);
		des_key_setup(&key[8],schedule[1],!mode);
		des_key_setup(&key[0],schedule[2],mode);
	}
}

void three_des_crypt(const BYTE in[], BYTE out[], const BYTE key[][16][6])
{
	des_crypt(in,out,key[0]);
	des_crypt(out,out,key[1]);
	des_crypt(out,out,key[2]);
}

/* DES remaining Code Ends */

int des_test()
{
	BYTE pt1[DES_BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xE7};
	BYTE pt2[DES_BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
	BYTE pt3[DES_BLOCK_SIZE] = {0x54,0x68,0x65,0x20,0x71,0x75,0x66,0x63};
	BYTE ct1[DES_BLOCK_SIZE] = {0xc9,0x57,0x44,0x25,0x6a,0x5e,0xd3,0x1d};
	BYTE ct2[DES_BLOCK_SIZE] = {0x85,0xe8,0x13,0x54,0x0f,0x0a,0xb4,0x05};
	BYTE ct3[DES_BLOCK_SIZE] = {0xc9,0x57,0x44,0x25,0x6a,0x5e,0xd3,0x1d};
	BYTE ct4[DES_BLOCK_SIZE] = {0xA8,0x26,0xFD,0x8C,0xE5,0x3B,0x85,0x5F};
	BYTE key1[DES_BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
	BYTE key2[DES_BLOCK_SIZE] = {0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1};
	BYTE three_key1[DES_BLOCK_SIZE * 3] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
	                                       0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
	                                       0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
	BYTE three_key2[DES_BLOCK_SIZE * 3] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
	                                       0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0x01,
	                                       0x45,0x67,0x89,0xAB,0xCD,0xEF,0x01,0x23};

	BYTE schedule[16][6];
	BYTE three_schedule[3][16][6];
	BYTE buf[DES_BLOCK_SIZE];
	int pass = 1;

	des_key_setup(key1, schedule, DES_ENCRYPT);
	des_crypt(pt1, buf, schedule);
	pass = pass && !memcmp(ct1, buf, DES_BLOCK_SIZE);

	des_key_setup(key1, schedule, DES_DECRYPT);
	des_crypt(ct1, buf, schedule);
	pass = pass && !memcmp(pt1, buf, DES_BLOCK_SIZE);

	des_key_setup(key2, schedule, DES_ENCRYPT);
	des_crypt(pt2, buf, schedule);
	pass = pass && !memcmp(ct2, buf, DES_BLOCK_SIZE);

	des_key_setup(key2, schedule, DES_DECRYPT);
	des_crypt(ct2, buf, schedule);
	pass = pass && !memcmp(pt2, buf, DES_BLOCK_SIZE);

	three_des_key_setup(three_key1, three_schedule, DES_ENCRYPT);
	three_des_crypt(pt1, buf, three_schedule);
	pass = pass && !memcmp(ct3, buf, DES_BLOCK_SIZE);

	three_des_key_setup(three_key1, three_schedule, DES_DECRYPT);
	three_des_crypt(ct3, buf, three_schedule);
	pass = pass && !memcmp(pt1, buf, DES_BLOCK_SIZE);

	three_des_key_setup(three_key2, three_schedule, DES_ENCRYPT);
	three_des_crypt(pt3, buf, three_schedule);
	pass = pass && !memcmp(ct4, buf, DES_BLOCK_SIZE);

	three_des_key_setup(three_key2, three_schedule, DES_DECRYPT);
	three_des_crypt(ct4, buf, three_schedule);
	pass = pass && !memcmp(pt3, buf, DES_BLOCK_SIZE);

	return(pass);
}

///////////////////////////////CHACHA 20/////////////
///////////////////////////////////////////////////////////////////////////////////////
#define __USE_MINGW_ANSI_STDIO 1
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#ifdef __WIN32__
#include <malloc.h>
#elif defined(__linux__) || defined(__sun__)
#include <alloca.h>
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#include <stdint.h>
#include <stdlib.h>

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))

#define LE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
  uint32_t schedule[16];
  uint32_t keystream[16];
  size_t available;
} chacha20_ctx;

//Call this to initilize a chacha20_ctx, must be called before all other functions

void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, size_t length, uint8_t nonce[8])
{
  const char *constants = (length == 32) ? "expand 32-byte k" : "expand 16-byte k";

  ctx->schedule[0] = LE(constants + 0);
  ctx->schedule[1] = LE(constants + 4);
  ctx->schedule[2] = LE(constants + 8);
  ctx->schedule[3] = LE(constants + 12);
  ctx->schedule[4] = LE(key + 0);
  ctx->schedule[5] = LE(key + 4);
  ctx->schedule[6] = LE(key + 8);
  ctx->schedule[7] = LE(key + 12);
  ctx->schedule[8] = LE(key + 16 % length);
  ctx->schedule[9] = LE(key + 20 % length);
  ctx->schedule[10] = LE(key + 24 % length);
  ctx->schedule[11] = LE(key + 28 % length);
  //Surprise! This is really a block cipher in CTR mode
  ctx->schedule[12] = 0; //Counter
  ctx->schedule[13] = 0; //Counter
  ctx->schedule[14] = LE(nonce+0);
  ctx->schedule[15] = LE(nonce+4);

  ctx->available = 0;
}

void chacha20_counter_set(chacha20_ctx *ctx, uint64_t counter)
{
  ctx->schedule[12] = counter & UINT32_C(0xFFFFFFFF);
  ctx->schedule[13] = counter >> 32;
  ctx->available = 0;
}

#define QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

void chacha20_block(chacha20_ctx *ctx, uint32_t output[16])
{
  uint32_t *const nonce = ctx->schedule+12; //12 is where the 128 bit counter is
  int i = 10;

  memcpy(output, ctx->schedule, sizeof(ctx->schedule));

  while (i--)
  {
    QUARTERROUND(output, 0, 4, 8, 12)
    QUARTERROUND(output, 1, 5, 9, 13)
    QUARTERROUND(output, 2, 6, 10, 14)
    QUARTERROUND(output, 3, 7, 11, 15)
    QUARTERROUND(output, 0, 5, 10, 15)
    QUARTERROUND(output, 1, 6, 11, 12)
    QUARTERROUND(output, 2, 7, 8, 13)
    QUARTERROUND(output, 3, 4, 9, 14)
  }
  for (i = 0; i < 16; ++i)
  {
    uint32_t result = output[i] + ctx->schedule[i];
    FROMLE((uint8_t *)(output+i), result);
  }

  /*
  Official specs calls for performing a 64 bit increment here, and limit usage to 2^64 blocks.
  However, recommendations for CTR mode in various papers recommend including the nonce component for a 128 bit increment.
  This implementation will remain compatible with the official up to 2^64 blocks, and past that point, the official is not intended to be used.
  This implementation with this change also allows this algorithm to become compatible for a Fortuna-like construct.
  */
  if (!++nonce[0] && !++nonce[1] && !++nonce[2]) { ++nonce[3]; }
}

static inline void chacha20_xor(uint8_t *keystream, const uint8_t **in, uint8_t **out, size_t length)
{
  uint8_t *end_keystream = keystream + length;
  do { *(*out)++ = *(*in)++ ^ *keystream++; } while (keystream < end_keystream);
}

void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t length)
{
  if (length)
  {
    uint8_t *const k = (uint8_t *)ctx->keystream;

    //First, use any buffered keystream from previous calls
    if (ctx->available)
    {
      size_t amount = MIN(length, ctx->available);
      chacha20_xor(k + (sizeof(ctx->keystream)-ctx->available), &in, &out, amount);
      ctx->available -= amount;
      length -= amount;
    }

    //Then, handle new blocks
    while (length)
    {
      size_t amount = MIN(length, sizeof(ctx->keystream));
      chacha20_block(ctx, ctx->keystream);
      chacha20_xor(k, &in, &out, amount);
      length -= amount;
      ctx->available = sizeof(ctx->keystream) - amount;
    }
  }
}

void chacha20_decrypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t length)
{
  chacha20_encrypt(ctx, in, out, length);
}



void hex2byte(const char *hex, uint8_t *byte)
{
  while (*hex) { sscanf(hex, "%2hhx", byte++); hex += 2; }
}

void test_keystream(const char *text_key, const char *text_nonce, const char *text_value, unsigned int number)
{
  chacha20_ctx ctx;
  uint32_t output[16];
  unsigned int i = 0;
  uint8_t key[32];
  uint8_t nonce[8];
  size_t value_len = strlen(text_value) / 2;
  uint8_t *value = alloca(value_len);

 // printf("Test Vector: Keystream #%u: ", number);

  hex2byte(text_key, key);
  hex2byte(text_nonce, nonce);
  hex2byte(text_value, value);
  chacha20_setup(&ctx, key, sizeof(key), nonce);

  while (i < value_len)
  {
    chacha20_block(&ctx, output);
    if (memcmp(output, value+i, MIN(sizeof(output), value_len-i)))
    {
 //     puts("Failed");
      return;
    }
    i += sizeof(output);
  }
 // puts("Success");
}

void test_encipherment(const char *text_key, const char *text_nonce, const char *text_plain, const char *text_cipher, uint64_t counter, unsigned int number)
{
  chacha20_ctx ctx;
  size_t i = 0;
  uint8_t key[32];
  uint8_t nonce[8];
  size_t len = strlen(text_plain) / 2;
  uint8_t *plain = alloca(len);
  uint8_t *cipher = alloca(len);
  uint8_t *output = alloca(len);

 // printf("Test Vector: Encipherment #%u: ", number);

  hex2byte(text_key, key);
  hex2byte(text_nonce, nonce);
  hex2byte(text_plain, plain);
  hex2byte(text_cipher, cipher);
  chacha20_setup(&ctx, key, sizeof(key), nonce);

  //Exact length test
  memset(output, 0, len);
  chacha20_counter_set(&ctx, counter);
  chacha20_encrypt(&ctx, plain, output, len);
  if (memcmp(output, cipher, len))
  {
   // puts("Failed exact length");
    return;
  }
  //Fixed length tests
  while (i < len)
  {
    size_t j;
    ++i;
    memset(output, 0, len);
    chacha20_counter_set(&ctx, counter);
    for (j = 0; j < len; j += i)
    {
      chacha20_encrypt(&ctx, plain+j, output+j, MIN(i, len-j));
    }
    if (memcmp(output, cipher, len))
    {
     // printf("Failed at round: %zu\n", i);
      return;
    }
  }
  //Random length tests
  for (i = 0; i < 1000; ++i)
  {
    size_t amount, j;
    memset(output, 0, len);
    chacha20_counter_set(&ctx, counter);
    for (j = 0; j < len; j += amount)
    {
      amount = rand() & 15;
      chacha20_encrypt(&ctx, plain+j, output+j, MIN(amount, len-j));
    }
    if (memcmp(output, cipher, len))
    {
      //puts("Failed random tests 1");
      return;
    }
  }
  //Random length tests 2
  for (i = 0; i < 1000; ++i)
  {
    size_t amount, j;
    memset(output, 0, len);
    chacha20_counter_set(&ctx, counter);
    for (j = 0; j < len; j += amount)
    {
      amount = 65 + (rand() & 63);
      chacha20_encrypt(&ctx, plain+j, output+j, MIN(amount, len-j));
    }
    if (memcmp(output, cipher, len))
    {
      //puts("Failed random tests 2");
      return;
    }
  }
  //puts("Success");
}

int chachaTEST()
{
     srand(0); //Test results will be consistent
  //http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
  test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", 1);
  test_keystream("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000", "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963", 2);
  test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000001", "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3", 3);
  test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000", "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b", 4);
  test_keystream("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "0001020304050607", "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9", 5);
  //http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04#appendix-A.2
  test_encipherment("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", 0, 1);
  test_encipherment("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000002", "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f", "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221", 1, 2);
  test_encipherment("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "0000000000000002", "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e", "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1", 42, 3);
 srand(0); //Test results will be consistent
  //http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
  test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", 1);
  test_keystream("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000", "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963", 2);
  test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000001", "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3", 3);
  test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000", "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b", 4);
  test_keystream("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "0001020304050607", "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9", 5);
  //http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04#appendix-A.2
  test_encipherment("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", 0, 1);
  test_encipherment("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000002", "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f", "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221", 1, 2);
  test_encipherment("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "0000000000000002", "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e", "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1", 42, 3);
 return 1 ;
}
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////CHACHA20/////////////


///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////  RSA TEST///////////////////////////
//////////////////////////////////////////////////////////////////////////////////
// Some useful data structures
typedef unsigned char byte;
#define BIGNUM_MAX_BYTES 1024 // The max size of a bignum, with 1k we should be able to handle RSA-2048 bits easily
typedef struct bignum {
  byte bytes[BIGNUM_MAX_BYTES]; // Stored least-significant first
} bignum;

// Some sample data
char *p_str = "dd755ca44f2f399a845690ef8507365befef9505fbf416cb0b306bd13221a00368e8bd45f7357d2686b8437816da326dc40b7c756d2407bb9a8c8a3fb2b8e79d";
char *q_str = "e083f0abbd0bee477bc86aa12077b82b5f7a035ac614dd494fa55a57e03deea0527f54e31e715374b3dd992ea9f80bb94b7e3b2b4e02e8901af79e688c1c7483";
char *e_str = "010001";
char *n_str = "c238d450c526bb2014b1489505540eb8330c7e01ed7ac4a7d9a52423025f9bdd5eb42b2103b6a069e43678bef68fa67703c304c590c6629bd455f4d8c0a145599df37bdefa19b52532937a2ccc22fb36f73c6dad819bc01e1326028fab37a052e0efae05e437573f2254a5ea4a43d1f3dbec2b22bf24fc6dddd0443f6ebda957";
char *d_str = "305bf211826558666e808deffcf9a7089a3d5c0aa2d4d4ae6e74be00b19098c08fda107b11efa1157cab4b7950ef07a5ce9bfa4e2ef4168d725b4cb1c394e42d332999fa20a42f4c31fdeba079c6931a11915f66d2b47c75571d334ce075bc417df8bc0848ae97b7abf6472ab7c83de2da691115a864d32496200d26a1d91791";
char *message = "This is going to be embarrasing if it doesn't work!";
char *m_str = "5468697320697320676f696e6720746f20626520656d626172726173696e6720696620697420646f65736e277420776f726b21";
char *c_str = "68c1a28435c90c20e3e0111302f97222c875215ce37178cdca30fbd90fceafaa7aa90c5d0dee2290a3b4cf944a177175acd5cb29cb03869bce2b4f93357cb94b08f8f1f08f793f9a7015338be19ff6b9301aa144665ffe0f7749885d3c3a51f8627d1e26ad629525eee59da7d5c69fe2926b6fb51ded336b6033a203d1ef5bc3";

// Some bignum functions

// Parse two chars as hex
int parse_hex_byte(char *input, int offset) {
  char temp[3];
  temp[0]=input[offset];
  temp[1]=input[offset+1];
  temp[2]=0;
  int val;
  sscanf(temp,"%x",&val);
  return val;
}

// Convert an even-digits string eg "010001" to a bignum
void string_to_bignum(char *input, bignum *output) {
  memset(output,0,sizeof(bignum)); // Clear the bignum first
  int bytes = strlen(input)/2; // Figure out how many bytes there'll be
  for (int i=0;i<bytes;i++) {
    output->bytes[i] = parse_hex_byte(input,(bytes-i-1)*2);
  }
}

// Find the number of significant bytes in the bignum
int bignum_length(bignum *val) {
  int len=1;
  // Look for the highest nonzero byte
  for (int i=0;i<BIGNUM_MAX_BYTES;i++) {
    if (val->bytes[i]) {
      len = i+1;
    }
  }
  return len;
}

// Print a bignum to screen
void print_bignum(bignum *val, char *message) {
  printf ("%s:\r\n ", message);
  for (int i=bignum_length(val)-1;i>=0;i--) {
    printf ("%02x",val->bytes[i]);
  }
  printf ("\r\n");
}

// Add a + b, storing the result in a
void bignum_add(bignum *a, bignum *b) {
  int carry=0;
  for (int i=0;i<BIGNUM_MAX_BYTES;i++) {
    int newval = a->bytes[i] + b->bytes[i] + carry;
    a->bytes[i] = newval % 256;
    carry = newval / 256;
  }
}

// Do a -= b, storing the result in a, returning nonzero if b is bigger
int bignum_subtract(bignum *a, bignum *b) {
  int borrow=0;
  for (int i=0;i<BIGNUM_MAX_BYTES;i++) {
    int newval = a->bytes[i] - b->bytes[i] - borrow;
    if (newval<0) {
      newval+=256;
      borrow=1;
    }
    else {
      borrow=0;
    }
    a->bytes[i] = newval;
  }
  return borrow;
}

// Returns nonzero if a >= b
int bignum_gte(bignum *a, bignum *b) {
  // First check if they're equal
  if (!memcmp(a,b,sizeof(bignum))) return 1;
  // Now do a subtract to find which is bigger
  int borrow=0;
  for (int i=0;i<BIGNUM_MAX_BYTES;i++) {
    int newval = b->bytes[i] - a->bytes[i] - borrow;
    if (newval<0) {
      borrow=1;
    }
    else {
      borrow=0;
    }
  }
  return borrow;
}

// Multiply a bignum by 1 digit
void bignum_mult1(bignum *a, bignum *out, int mult) {
  int carry=0;
  for (int i=0;i<BIGNUM_MAX_BYTES;i++) {
    int newval = a->bytes[i] * mult + carry;
    out->bytes[i] = newval % 256;
    carry = newval / 256;
  }
}

// Shift left by whole digits, eg make a bignum even bigger
void bignum_shiftleft_8bits(bignum *a, int digits) {
  if (digits==0) return;
  memcpy(a->bytes+digits,a->bytes,BIGNUM_MAX_BYTES-digits); // Move the digits
  memset(a->bytes,0,digits); // zero out the new bottom digits
}

// Shifts a bignum left one bit (making it bigger)
void bignum_shiftleft_onebit(bignum *a) {
  for (int i=BIGNUM_MAX_BYTES-1;i>0;i--) {
    a->bytes[i] = (a->bytes[i]<<1) + (a->bytes[i-1]>>7); // Shift this one left, and grab the high bit from below
  }
  a->bytes[0] <<= 1; // Sort out the smallest byte (it can't grab a bit)
}

// Shifts a bignum right one bit (making it smaller)
void bignum_shiftright_onebit(bignum *a) {
  for (int i=0;i<BIGNUM_MAX_BYTES-1;i++) {
    a->bytes[i] = (a->bytes[i]>>1) + ((a->bytes[i+1]&1)<<7); // Shift this one right, plus borrow a bit from the next
  }
  a->bytes[BIGNUM_MAX_BYTES-1] >>= 1; // Sort out the last byte (it can't borrow a bit)
}

// Multiply two bignums, storing the result in a
// Uses the method you were taught at school. Not the fastest but it'll do.
void bignum_mult(bignum *a, bignum *b, bignum *out) {
  bignum temp; // This is used to store the multiplication by each digit
  memset(&temp,0,sizeof(bignum)); // Clear the bignum first
  memset(out ,0,sizeof(bignum)); // Clear the bignum first
  for (int i=0;i<BIGNUM_MAX_BYTES;i++) {
    if (b->bytes[i]) { // Save time by skipping multiplying by zero columns
      bignum_mult1(a,&temp,b->bytes[i]); // temp = a * single-digit-from-b
      bignum_shiftleft_8bits(&temp,i); // temp is shifted to line up with the column we're using from b
      bignum_add(out,&temp); // Add temp to the running total
    }
  }
}

// Do a/b, and store the remainder in out
// This uses the shift and subtract method
void bignum_mod(bignum *a, bignum *b, bignum *out) {
  memcpy(out,a,sizeof(bignum)); // Start off with out=a, and whittle it down
  // Get the lengths
  int len_a = bignum_length(a);
  int len_b = bignum_length(b);
  if (len_b>len_a) return; // Simple case: since b is bigger, a is already the modulus
  // Start by shifting b so it's bigger than a
  bignum shifted;
  int byte_shifts = len_a-len_b+1;
  memcpy(&shifted,b,sizeof(bignum)); // Shifted is b, shifted to all sizes
  bignum_shiftleft_8bits(&shifted,byte_shifts); // Now b is bigger than a
  bignum temp;
  // Now do a series of bit shifts on B, subtracting it from A each time
  for (int i=0;i<byte_shifts*8;i++) {
    bignum_shiftright_onebit(&shifted);

    if (bignum_gte(out,&shifted))
      bignum_subtract(out,&shifted);
  }
}

// Returns nonzero if a>0
int bignum_gzero(bignum *a) {
  for (int i=0;i<BIGNUM_MAX_BYTES;i++) {
    if (a->bytes[i]!=0) return 1;
  }
  return 0;
}

// Do base ^ power % mod
// This does modular exponentiation using the right-to-left binary method
// This is actually quite slow, mainly due to the mod function, but also the mult is slow too
void bignum_modpow(bignum *in_base, bignum *in_power, bignum *mod, bignum *result) {
  bignum temp, base, power;
  memcpy(&base,in_base,sizeof(bignum)); // base = in_base (so we don't clobber the input)
  memcpy(&power,in_power,sizeof(bignum)); // power = in_power (so we don't clobber the input)

  string_to_bignum("01", result); // result = 1

  while(bignum_gzero(&power)) { // while power > 0
    if (power.bytes[0]&1) {
      bignum_mult(result,&base,&temp); // temp = result*base
      bignum_mod(&temp,mod,result); // result = temp % mod
    }
    bignum_mult(&base,&base,&temp); // temp = base*base
    bignum_mod(&temp,mod,&base); // base = temp % mod
    bignum_shiftright_onebit(&power); // power>>=1
  }
}

// Generates a big number up to the value of the maximum
void bignum_rand(bignum *max,bignum *out) {
  int len = bignum_length(max);
  for (int i=0;i<BIGNUM_MAX_BYTES;i++) {
    if (i<len-1) // For bytes less significant than the last one, make them random 0..255
      out->bytes[i] = rand() % 256;
    if (i==len-1) // For the byte of highest significance, make it random but not higher than max
      out->bytes[i] = rand() % max->bytes[i];
    if (i>=len) // For the restof the higher significance bytes, make then zero
      out->bytes[i] = 0;
  }
}

// Do a miller-rabin primality test
// This is a C port of the code found here: http://snippets.dzone.com/posts/show/4636
// This is unworkably slow, i think due to the mod and mult functions
int bignum_isprime(bignum *n) {
  bignum temp[7]; // Set up some handy bignums
  string_to_bignum("00", &temp[0]); // temp[0]=0
  string_to_bignum("01", &temp[1]); // temp[1]=1
  string_to_bignum("02", &temp[2]); // ...
  string_to_bignum("03", &temp[3]);
  string_to_bignum("04", &temp[4]);
  string_to_bignum("05", &temp[5]);
  string_to_bignum("06", &temp[6]);

  if (!memcmp(n,&temp[2],sizeof(bignum))) return 1; // return true if n == 2
  if (!memcmp(n,&temp[1],sizeof(bignum))) return 0; // return false if n == 1
//  if (n->bytes[0] & 1 == 0) return false; // return false n & 1 == 0 (even number test)

  int gt3 = bignum_gte(n, &temp[4]); // Is n > 3? (aka n>=4)
  bignum mod6; bignum_mod(n, &temp[6], &mod6); //  mod6 = n % 6
  int mod6not1 = memcmp(&mod6,&temp[1],sizeof(bignum)); // mod6not1 true if mod6 != 1
  int mod6not5 = memcmp(&mod6,&temp[5],sizeof(bignum)); // mod6not5 true if mod6 != 5
  if (gt3 && mod6not1 && mod6not5) return 0; // return false if n > 3 && n % 6 != 1 && n % 6 != 5

  bignum d;
  memcpy(&d,n,sizeof(bignum)); // d = n
  bignum_subtract(&d,&temp[1]); // d = n-1

  while (d.bytes[0] & 1 == 0) bignum_shiftright_onebit(&d); // d >>= 1 while d & 1 == 0

  bignum nsub1, nsub2;
  memcpy(&nsub1,n,sizeof(bignum)); // nsub1 = n
  bignum_subtract(&nsub1,&temp[1]); // nsub1 = n-1
  memcpy(&nsub2,n,sizeof(bignum)); // nsub2 = n
  bignum_subtract(&nsub2,&temp[2]); // nsub2 = n-2

  for (int k=0;k<20;k++) { // 20.times do
    bignum a; // Do: a = rand(n-2) + 1
    bignum_rand(&nsub2,&a); // a = rand(n-2)
    bignum_add(&a,&temp[1]); // a += 1

    bignum t;
    memcpy(&t,&d,sizeof(bignum)); // t = d

    bignum y;
    bignum_modpow(&a, &t, n, &y); // y = mod_pow(a,t,n)

    // while t != n-1 && y != 1 && y != n-1
    while (memcmp(&t, &nsub1, sizeof(bignum)) &&
           memcmp(&y, &temp[1], sizeof(bignum)) &&
           memcmp(&y, &nsub1, sizeof(bignum))) {
      bignum ysqr; // Do: y = (y*y) % n
      bignum_mult(&y,&y,&ysqr); // ysqr = y*y
      bignum_mod(&ysqr,n,&y); // y = ysqr % n

      bignum_shiftleft_onebit(&t); // t <<= 1
    }

    // return false if y != n-1 && t & 1 == 0
    if (memcmp(&y, &nsub1, sizeof(bignum)) && t.bytes[0]&1==0) return 0;
  }
  return 1;
}

int rsa_test()
{
    srand(time(NULL)); // Seed the randomiser

  bignum p, q, n, m, e, d;
  string_to_bignum(p_str, &p);
  string_to_bignum(q_str, &q);
  string_to_bignum(n_str, &n);
  string_to_bignum(m_str, &m);
  string_to_bignum(e_str, &e);
  string_to_bignum(d_str, &d);

  // Test encryption
  bignum c;
  bignum_modpow(&m, &e, &n, &c); // Encrypt: c = m^e mod n
 // print_bignum(&c, "C cryptotext");

  // Decryption
 // printf ("Decrypting...\r\n");
  bignum a;
  bignum_modpow(&c, &d, &n, &a); // Decrypt: a = c^d mod n
 // print_bignum(&a, "Decrypted");
}


///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////  RSA TEST///////////////////////////
//////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////
/////////////////////////3 DES START TEST///////////////////////////
//////////////////////////////////////////////////////////////////////////////////

typedef unsigned char byte;

// Here are all the lookup tables for the row shifts, rcon, s-boxes, and galois field multiplications
static const byte shift_rows_table[]     = {0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11};
static const byte shift_rows_table_inv[] = {0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3};
static const byte lookup_rcon[] = {
    0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a
};
static const byte lookup_sbox[] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const byte lookup_sbox_inv[] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
static const byte lookup_g2[] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
    0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
    0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
    0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
    0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
    0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
    0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
    0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};
static const byte lookup_g3[] = {
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
    0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
    0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
    0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
    0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
    0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
    0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
    0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
    0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
    0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
    0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
    0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
    0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
    0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
    0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
    0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};
static const byte lookup_g9[] = {
    0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
    0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
    0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
    0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
    0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
    0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
    0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
    0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
    0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
    0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
    0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
    0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
    0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
    0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
    0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
    0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46
};
static const byte lookup_g11[] = {
    0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
    0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
    0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
    0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
    0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
    0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
    0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
    0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
    0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
    0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
    0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
    0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
    0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
    0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
    0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
    0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
};
static const byte lookup_g13[] = {
    0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
    0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
    0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
    0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
    0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
    0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
    0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
    0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
    0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
    0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
    0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
    0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
    0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
    0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
    0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
    0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97
};
static const byte lookup_g14[] = {
    0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
    0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
    0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
    0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
    0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
    0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
    0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
    0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
    0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
    0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
    0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
    0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
    0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
    0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
    0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
    0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
};

// Xor's all elements in a n byte array a by b
static void xor(byte *a, const byte *b, int n) {
    int i;
    for (i=0; i<n; i++) {
        a[i] ^= b[i];
    }
}

// Xor the current cipher state by a specific round key
static void xor_round_key(byte *state, const byte *keys, int round) {
    xor(state,keys+round*16,16);
}

// Apply and reverse the rijndael s-box to all elements in an array
// http://en.wikipedia.org/wiki/Rijndael_S-box
static void sub_bytes(byte *a,int n) {
    int i;
    for (i=0; i<n; i++) {
        a[i] = lookup_sbox[a[i]];
    }
}
static void sub_bytes_inv(byte *a,int n) {
    int i;
    for (i=0; i<n; i++) {
        a[i] = lookup_sbox_inv[a[i]];
    }
}

// Rotate the first four bytes of the input eight bits to the left
static inline void rot_word(byte *a) {
    byte temp = a[0];
    a[0]=a[1];
    a[1]=a[2];
    a[2]=a[3];
    a[3]=temp;
}

// Perform the core key schedule transform on 4 bytes, as part of the key expansion process
// http://en.wikipedia.org/wiki/Rijndael_key_schedule#Key_schedule_core
static void key_schedule_core(byte *a, int i) {
    byte temp = a[0];     // Rotate the output eight bits to the left
    a[0]=a[1];
    a[1]=a[2];
    a[2]=a[3];
    a[3]=temp;
    sub_bytes(a,4);       // Apply Rijndael's S-box on all four individual bytes in the output word
    a[0]^=lookup_rcon[i]; // On just the first (leftmost) byte of the output word, perform the rcon operation with i
    // as the input, and exclusive or the rcon output with the first byte of the output word
}

// Expand the 16-byte key to 11 round keys (176 bytes)
// http://en.wikipedia.org/wiki/Rijndael_key_schedule#The_key_schedule
static void expand_key128(const byte *key, byte *keys) {
    int bytes=16;             // The count of how many bytes we've created so far
    int i=1;                  // The rcon iteration value i is set to 1
    int j;                    // For repeating the second stage 3 times
    byte t[4];                // Temporary working area known as 't' in the Wiki article
    memcpy(keys,key,16);      // The first 16 bytes of the expanded key are simply the encryption key

    while (bytes<176) {       // Until we have 176 bytes of expanded key, we do the following:
        memcpy(t,keys+bytes-4,4);          // We assign the value of the previous four bytes in the expanded key to t
        key_schedule_core(t, i);           // We perform the key schedule core on t, with i as the rcon iteration value
        i++;                               // We increment i by 1
        xor(t,keys+bytes-16,4);            // We exclusive-or t with the four-byte block 16 bytes before the new expanded key.
        memcpy(keys+bytes,t,4);            // This becomes the next 4 bytes in the expanded key
        bytes+=4;                          // Keep track of how many expanded key bytes we've added

        // We then do the following three times to create the next twelve bytes
        for (j=0; j<3; j++) {
            memcpy(t,keys+bytes-4,4);          // We assign the value of the previous 4 bytes in the expanded key to t
            xor(t,keys+bytes-16,4);            // We exclusive-or t with the four-byte block n bytes before
            memcpy(keys+bytes,t,4);            // This becomes the next 4 bytes in the expanded key
            bytes+=4;                          // Keep track of how many expanded key bytes we've added
        }
    }
}

// Expand the 32-byte key to 15 round keys (240 bytes)
// http://en.wikipedia.org/wiki/Rijndael_key_schedule#The_key_schedule
static void expand_key256(const byte *key, byte *keys) {
    int i=0;                                      // The count of how many iterations we've done
    byte t[4];                                    // Temporary working area

    // The first 32 bytes of the expanded key are simply the encryption key
    memcpy(keys, key, 8 * 4);

    // The remaining 240-32 bytes of the expanded key are computed in one of three ways:
    for (i = 8; i < 4 * 15; i++) {
        if (i % 8 == 0) {
            memcpy(t, keys + 4 * (i - 1), 4);     // We assign the value of the previous 4 bytes in the expanded key to t
            sub_bytes(t, 4);                      // We apply byte-wise substitution to t
            rot_word(t);                          // We rotate t one byte left
            t[0] ^= lookup_rcon[i / 8];           // We xor in the round constant
            xor(t, keys + 4 * (i - 8), 4);        // We xor in the four-byte block n bytes before
            memcpy(keys + 4 * i, t, 4);           // This becomes the next 4 bytes in the expanded key
        } else if (i % 8 == 4) {
            memcpy(t, keys + 4 * (i - 1), 4);     // We assign the value of the previous 4 bytes in the expanded key to t
            sub_bytes(t, 4);                      // We apply byte-wise substitution to t
            xor(t, keys + 4 * (i - 8), 4);        // We xor in the four-byte block n bytes before
            memcpy(keys + 4 * i, t, 4);           // This becomes the next 4 bytes in the expanded key
        } else {
            memcpy(t, keys + 4 * (i - 1), 4);     // We assign the value of the previous 4 bytes in the expanded key to t
            xor(t, keys + 4 * (i - 8), 4);        // We xor in the four-byte block n bytes before
            memcpy(keys + 4 * i, t, 4);           // This becomes the next 4 bytes in the expanded key
        }
    }
}

// Apply / reverse the shift rows step on the 16 byte cipher state
// http://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
static void shift_rows(byte *state) {
    int i;
    byte temp[16];
    memcpy(temp,state,16);
    for (i=0; i<16; i++) {
        state[i]=temp[shift_rows_table[i]];
    }
}
static void shift_rows_inv(byte *state) {
    int i;
    byte temp[16];
    memcpy(temp,state,16);
    for (i=0; i<16; i++) {
        state[i]=temp[shift_rows_table_inv[i]];
    }
}

// Perform the mix columns matrix on one column of 4 bytes
// http://en.wikipedia.org/wiki/Rijndael_mix_columns
static void mix_col (byte *state) {
    byte a0 = state[0];
    byte a1 = state[1];
    byte a2 = state[2];
    byte a3 = state[3];
    state[0] = lookup_g2[a0] ^ lookup_g3[a1] ^ a2 ^ a3;
    state[1] = lookup_g2[a1] ^ lookup_g3[a2] ^ a3 ^ a0;
    state[2] = lookup_g2[a2] ^ lookup_g3[a3] ^ a0 ^ a1;
    state[3] = lookup_g2[a3] ^ lookup_g3[a0] ^ a1 ^ a2;
}

// Perform the mix columns matrix on each column of the 16 bytes
static void mix_cols (byte *state) {
    mix_col(state);
    mix_col(state+4);
    mix_col(state+8);
    mix_col(state+12);
}

// Perform the inverse mix columns matrix on one column of 4 bytes
// http://en.wikipedia.org/wiki/Rijndael_mix_columns
static void mix_col_inv (byte *state) {
    byte a0 = state[0];
    byte a1 = state[1];
    byte a2 = state[2];
    byte a3 = state[3];
    state[0] = lookup_g14[a0] ^ lookup_g9[a3] ^ lookup_g13[a2] ^ lookup_g11[a1];
    state[1] = lookup_g14[a1] ^ lookup_g9[a0] ^ lookup_g13[a3] ^ lookup_g11[a2];
    state[2] = lookup_g14[a2] ^ lookup_g9[a1] ^ lookup_g13[a0] ^ lookup_g11[a3];
    state[3] = lookup_g14[a3] ^ lookup_g9[a2] ^ lookup_g13[a1] ^ lookup_g11[a0];
}

// Perform the inverse mix columns matrix on each column of the 16 bytes
static void mix_cols_inv (byte *state) {
    mix_col_inv(state);
    mix_col_inv(state+4);
    mix_col_inv(state+8);
    mix_col_inv(state+12);
}

// Encrypt a single 128 bit block by a 128 bit key using AES
// http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
static void EncryptAES128(const byte *msg, const byte *key, byte *c) {
    int i; // To count the rounds

    // Key expansion
    byte keys[176];
    expand_key128(key,keys);

    // First Round
    memcpy(c, msg, 16);
    xor_round_key(c,keys,0);

    // Middle rounds
    for(i=0; i<9; i++) {
        sub_bytes(c,16);
        shift_rows(c);
        mix_cols(c);
        xor_round_key(c, keys, i+1);
    }

    // Final Round
    sub_bytes(c,16);
    shift_rows(c);
    xor_round_key(c, keys, 10);
}

// Encrypt a single 128 bit block by a 256 bit key using AES
// http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
static void EncryptAES256(const byte *msg, const byte *key, byte *c) {
    int i; // To count the rounds

    // Key expansion
    byte keys[240];
    expand_key256(key,keys);

    // First Round
    memcpy(c, msg, 16);
    xor_round_key(c,keys,0);

    // Middle rounds
    for(i=0; i<13; i++) {
        sub_bytes(c,16);
        shift_rows(c);
        mix_cols(c);
        xor_round_key(c, keys, i+1);
    }

    // Final Round
    sub_bytes(c,16);
    shift_rows(c);
    xor_round_key(c, keys, 14);
}

// Decrypt a single 128 bit block by a 128 bit key using AES
// http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
static void DecryptAES128(const byte *c, const byte *key, byte *m) {
    int i; // To count the rounds

    // Key expansion
    byte keys[176];
    expand_key128(key,keys);

    // Reverse the final Round
    memcpy(m,c,16);
    xor_round_key(m,keys,10);
    shift_rows_inv(m);
    sub_bytes_inv(m, 16);

    // Reverse the middle rounds
    for (i=0; i<9; i++) {
        xor_round_key(m,keys,9-i);
        mix_cols_inv(m);
        shift_rows_inv(m);
        sub_bytes_inv(m, 16);
    }

    // Reverse the first Round
    xor_round_key(m, keys, 0);
}

// Decrypt a single 128 bit block by a 256 bit key using AES
// http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
static void DecryptAES256(const byte *c, const byte *key, byte *m) {
    int i; // To count the rounds

    // Key expansion
    byte keys[240];
    expand_key256(key,keys);

    // Reverse the final Round
    memcpy(m,c,16);
    xor_round_key(m,keys,14);
    shift_rows_inv(m);
    sub_bytes_inv(m, 16);

    // Reverse the middle rounds
    for (i=0; i<13; i++) {
        xor_round_key(m,keys,13-i);
        mix_cols_inv(m);
        shift_rows_inv(m);
        sub_bytes_inv(m, 16);
    }

    // Reverse the first Round
    xor_round_key(m, keys, 0);
}

// Pretty-print a key (or any smallish buffer) onto screen as hex
static void Pretty(const byte* b,int len,char* label) {
    printf("%s", label);
    int i;
    for (i=0; i<len; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

int test_expand_key_128() {
    // test vector from Appendix A.1 of FIPS 197
    byte key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte expected_keys[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05, 0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f, 0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b, 0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00, 0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc, 0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd, 0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f, 0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f, 0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e, 0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6};
    byte keys[176];

    // printf("\nTest AES128 key expansion\n");
    expand_key128(key, keys);
    if (memcmp(keys, expected_keys, 176) == 0) {
      //  printf("Expanded key matches expected value.\n");
        return 0;
    } else {
      //  printf("Expanded key does not match expected value!\n");
        Pretty(expected_keys, 176, "Expected expanded key: ");
        Pretty(keys, 176, "Actual expanded key:   ");
        return -1;
    }
}

int test_encrypt_128() {
    // test vector from Appendix C.1 of FIPS 197
    byte plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    byte key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    byte expected_ciphertext[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    byte ciphertext[16];

    //printf("\nTest AES128 encryption\n");
    EncryptAES128(plaintext, key, ciphertext);


    if (memcmp(ciphertext, expected_ciphertext, 16) == 0) {
      //  printf("Ciphertext matches expected value.\n");
        return 0;
    } else {
      //  printf("Ciphertext does not match expected value!\n");
        Pretty(expected_ciphertext, 16, "Expected ciphertext: ");
        Pretty(ciphertext, 16, "Actual ciphertext:   ");
        return -2;
    }
}

int test_decrypt_128() {
    // test vector from Appendix C.1 of FIPS 197
    byte ciphertext[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    byte expected_plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    byte key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    byte plaintext[16];

    //printf("\nTest AES128 decryption\n");
    DecryptAES128(ciphertext, key, plaintext);
    if (memcmp(plaintext, expected_plaintext, 16) == 0) {
      //  printf("Plaintext matches expected value.\n");
        return 0;
    } else {
      //  printf("Plaintext does not match expected value!\n");
        Pretty(expected_plaintext, 16, "Expected plaintext: ");
        Pretty(plaintext, 16, "Actual plaintext:   ");
        return -4;
    }
}

int test_expand_key_256() {
    // test vector from Appendix A.3 of FIPS 197
    byte key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    byte expected_keys[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4, 0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a, 0x8b, 0x5f, 0x20, 0x67, 0xfc, 0xde, 0xa8, 0xb0, 0x9c, 0x1a, 0x93, 0xd1, 0x94, 0xcd, 0xbe, 0x49, 0x84, 0x6e, 0xb7, 0x5d, 0x5b, 0x9a, 0xd5, 0x9a, 0xec, 0xb8, 0x5b, 0xf3, 0xc9, 0x17, 0xfe, 0xe9, 0x42, 0x48, 0xde, 0x8e, 0xbe, 0x96, 0xb5, 0xa9, 0x32, 0x8a, 0x26, 0x78, 0xa6, 0x47, 0x98, 0x31, 0x22, 0x29, 0x2f, 0x6c, 0x79, 0xb3, 0x81, 0x2c, 0x81, 0xad, 0xda, 0xdf, 0x48, 0xba, 0x24, 0x36, 0x0a, 0xf2, 0xfa, 0xb8, 0xb4, 0x64, 0x98, 0xc5, 0xbf, 0xc9, 0xbe, 0xbd, 0x19, 0x8e, 0x26, 0x8c, 0x3b, 0xa7, 0x09, 0xe0, 0x42, 0x14, 0x68, 0x00, 0x7b, 0xac, 0xb2, 0xdf, 0x33, 0x16, 0x96, 0xe9, 0x39, 0xe4, 0x6c, 0x51, 0x8d, 0x80, 0xc8, 0x14, 0xe2, 0x04, 0x76, 0xa9, 0xfb, 0x8a, 0x50, 0x25, 0xc0, 0x2d, 0x59, 0xc5, 0x82, 0x39, 0xde, 0x13, 0x69, 0x67, 0x6c, 0xcc, 0x5a, 0x71, 0xfa, 0x25, 0x63, 0x95, 0x96, 0x74, 0xee, 0x15, 0x58, 0x86, 0xca, 0x5d, 0x2e, 0x2f, 0x31, 0xd7, 0x7e, 0x0a, 0xf1, 0xfa, 0x27, 0xcf, 0x73, 0xc3, 0x74, 0x9c, 0x47, 0xab, 0x18, 0x50, 0x1d, 0xda, 0xe2, 0x75, 0x7e, 0x4f, 0x74, 0x01, 0x90, 0x5a, 0xca, 0xfa, 0xaa, 0xe3, 0xe4, 0xd5, 0x9b, 0x34, 0x9a, 0xdf, 0x6a, 0xce, 0xbd, 0x10, 0x19, 0x0d, 0xfe, 0x48, 0x90, 0xd1, 0xe6, 0x18, 0x8d, 0x0b, 0x04, 0x6d, 0xf3, 0x44, 0x70, 0x6c, 0x63, 0x1e};
    byte keys[240];

    //printf("\nTest AES256 key expansion\n");
    expand_key256(key, keys);
    if (memcmp(keys, expected_keys, 240) == 0) {
      //  printf("Expanded key matches expected value.\n");
        return 0;
    } else {
      //  printf("Expanded key does not match expected value!\n");
        Pretty(expected_keys, 240, "Expected expanded key: ");
        Pretty(keys, 240, "Actual expanded key:   ");
        return -8;
    }
}

int test_encrypt_256() {
    // test vector from Appendix C.3 of FIPS 197
    byte plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    byte key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    byte expected_ciphertext[] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
    byte ciphertext[16];
    //plaintext = "What the hell is this man";
    //key = "474GEF7ER7FGC4RE7FGREUCOSDHCPD"

    //printf("\nTest AES256 encryption\n");
    EncryptAES256(plaintext, key, ciphertext);
        if (memcmp(ciphertext, expected_ciphertext, 16) == 0) {
        //printf("Ciphertext matches expected value.\n");
        return 0;
    } else {
        //printf("Ciphertext does not match expected value!\n");
        Pretty(expected_ciphertext, 16, "Expected ciphertext: ");
        Pretty(ciphertext, 16, "Actual ciphertext:   ");
        return -16;
    }
}

int test_decrypt_256() {
    // test vector from Appendix C.3 of FIPS 197
    byte ciphertext[] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
    byte expected_plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    byte key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    byte plaintext[16];

    //printf("\nTest AES256 decryption\n");
    DecryptAES256(ciphertext, key, plaintext);
    if (memcmp(plaintext, expected_plaintext, 16) == 0) {
      //  printf("Plaintext matches expected value.\n");
        return 0;
    } else {
        //printf("Plaintext does not match expected value!\n");
        Pretty(expected_plaintext, 16, "Expected plaintext: ");
        Pretty(plaintext, 16, "Actual plaintext:   ");
        return -32;
    }
}

///////////////////////////////////////////////////////////////////////////////////
/////////////////////////3 DES END TEST///////////////////////////
//////////////////////////////////////////////////////////////////////////////////

///////////////////////////
//////////////////////////
//////////////////////////

int vigenereCipher(char msg[], char key[])
{
     int msgLen = strlen(msg), keyLen = strlen(key), i, j;

    char newKey[msgLen], encryptedMsg[msgLen], decryptedMsg[msgLen];

    //generating new key
    for(i = 0, j = 0; i < msgLen; ++i, ++j){
        if(j == keyLen)
            j = 0;

        newKey[i] = key[j];
    }

    newKey[i] = '\0';

    //encryption
    for(i = 0; i < msgLen; ++i)
        encryptedMsg[i] = ((msg[i] + newKey[i]) % 26) + 'A';

    encryptedMsg[i] = '\0';

    //decryption
    for(i = 0; i < msgLen; ++i)
        decryptedMsg[i] = (((encryptedMsg[i] - newKey[i]) + 26) % 26) + 'A';

    decryptedMsg[i] = '\0';
   // printf("\r\nOriginal Message: %s", msg);
   // printf("\nKey: %s", key);
   // printf("\nNew Generated Key: %s", newKey);
   // printf("\nEncrypted Message: %s", encryptedMsg);
   // printf("\nDecrypted Message: %s", decryptedMsg);
  return 0;

}


int caesarCipher(char message[], int key)
{
   char ch ;
   int i;
   // Encryption Code
    for(i = 0; message[i] != '\0'; ++i){
        ch = message[i];

        if(ch >= 'a' && ch <= 'z'){
            ch = ch + key;

            if(ch > 'z'){
                ch = ch - 'z' + 'a' - 1;
            }

            message[i] = ch;
        }
        else if(ch >= 'A' && ch <= 'Z'){
            ch = ch + key;

            if(ch > 'Z'){
                ch = ch - 'Z' + 'A' - 1;
            }

            message[i] = ch;
        }
    }

    //printf("\rEncrypted message: %s", message);
   // Encryption Code

   //Decryption Code Starts
    for(i = 0; message[i] != '\0'; ++i){
        ch = message[i];

        if(ch >= 'a' && ch <= 'z'){
            ch = ch - key;

            if(ch < 'a'){
                ch = ch + 'z' - 'a' + 1;
            }

            message[i] = ch;
        }
        else if(ch >= 'A' && ch <= 'Z'){
            ch = ch - key;

            if(ch < 'A'){
                ch = ch + 'Z' - 'A' + 1;
            }

            message[i] = ch;
        }
    }

    //printf("\rDecrypted message: %s", message);
   //Decryption Code Ends
  return 0;
}

//////////////////////////
/////////////////////////
//////////////////////////




int main(int argc, char *argv[])
{
    aes_test();  // this function further contains the rest of the code which does the printing

    double tm1, tm2 ;
    clock_t st1,st2,end1,end2 ;
	int i,pass = 1,loop;

	st1 = clock();
    for(i=0; i<=1000; i++)
    {
    test_expand_key_128();
    test_encrypt_128();
    test_decrypt_128();
    }
    end1 = clock();

    st2 = clock();
    for(i=0; i<=1000; i++)
    {
    test_expand_key_256();
    test_encrypt_256();
    test_decrypt_256();
    }
    end2 = clock();

    tm1 =  (double)(end1-st1) / (double) CLOCKS_PER_SEC;
    tm2 =  (double)(end2-st2) / (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By AES 128 Bit Test is %f seconds",tm1);
    printf("\nTime Taken By AES 256 Bit Test is %f seconds",tm2);


    st1 = clock();
     for(loop=0; loop<=8200; loop++)
        {
          blowfish_test();
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By Blowfish Test is %f seconds",tm1);

     st1 = clock();
     for(loop=0; loop<=8200; loop++)
        {
          des_test();
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By DES + 3DES Test is %f seconds",tm1);

    st1 = clock();
     for(loop=0; loop<=12; loop++)
        {
          chachaTEST();
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By CHACHA Test is %f seconds",tm1);

     st1 = clock();
          rsa_test();
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By RSA Test is %f seconds",tm1);


     char str[] = "RAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKRAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKS";
    char chabi[] = "RAMMING SUCKSPROGRAMMING SUCKSPROGRAMMING SUCKS";

     st1 = clock();
     for(loop=0; loop<=10000; loop++)
        {
    caesarCipher(str,4);
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By Caesar Cipher (10000 rounds) Test is %f seconds",tm1);


     st1 = clock();
     for(loop=0; loop<=10000; loop++)
        {
    vigenereCipher(str,chabi);
        }
    end1= clock();
    tm1 = (double)(end1-st1)/ (double) CLOCKS_PER_SEC;
    printf("\nTime Taken By Vigenere Cipher (10000 rounds) Test is %f seconds",tm1);


	return(0);
}
