
/****************************************************************************************/
/*
 *  IMSE.CNM_SPIRS: RoT.h
 *
 *  Created on: 16/12/2023
 *      Author: Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
 *
 */
 /****************************************************************************************/

#ifndef ROT_SPIRS_H_INCLUDED
#define ROT_SPIRS_H_INCLUDED

#include <stdlib.h>

#include "RoT_SPIRS/src/common/common.h"
#include "RoT_SPIRS/src/sha2/sha2_hw.h"
#include "RoT_SPIRS/src/sha3/sha3_hw.h"
#include "RoT_SPIRS/src/eddsa/ECC_func.h"
#include "RoT_SPIRS/src/aes/aes_hw.h"
#include "RoT_SPIRS/src/puf/puf.h"

#define sha2_256		sha2_hw_256
#define sha3_512		sha3_hw_512
#define sign_eddsa		sign
#define verify_eddsa	verify
#define public_eddsa	gen_pub_key
#define aes_128_enc		aes_128_enc
#define aes_128_dec		aes_128_dec
#define aes_256_enc		aes_256_enc
#define aes_256_dec		aes_256_dec
#define puf				puf_as_puf
#define trng			puf_as_trng

// ------- MS2XL_BASEADDR ------- //

#define MS2XL_LENGTH   0x40

// Memory directions and size declaration

#if defined(PYNQZ2)
	#define MS2XL_BASEADDR_AES		0x43C10000
	#define MS2XL_BASEADDR_EDDSA	0x43C20000
	#define MS2XL_BASEADDR_SHA2_256 0x43C30000
	#define MS2XL_BASEADDR_SHA3_512 0x43C40000
	#define MS2XL_BASEADDR_PUF_1	0x43C50000
	#define MS2XL_BASEADDR_PUF_2	0x43C60000
#elif defined(G2RISCV)
	#if defined(IMSE)
		#define MS2XL_BASEADDR_AES		0x60050000
		#define MS2XL_BASEADDR_EDDSA	0x60060000
		#define MS2XL_BASEADDR_SHA2_256 0x60070000
		#define MS2XL_BASEADDR_SHA3_512 0x60080000
		#define MS2XL_BASEADDR_PUF_1	0x60090000
		#define MS2XL_BASEADDR_PUF_2	0x600A0000
	#elif defined(SPIRS)
		#define MS2XL_BASEADDR_AES		0x41000000
		#define MS2XL_BASEADDR_EDDSA	0x45000000
		#define MS2XL_BASEADDR_SHA2_256 0x43000000
		#define MS2XL_BASEADDR_SHA3_512 0x44000000
		#define MS2XL_BASEADDR_PUF_1	0x42000000
		#define MS2XL_BASEADDR_PUF_2	0x48000000		
	#endif
#else
	#define MS2XL_BASEADDR_AES		0x43C10000
	#define MS2XL_BASEADDR_EDDSA	0x43C20000
	#define MS2XL_BASEADDR_SHA2_256 0x43C30000
	#define MS2XL_BASEADDR_SHA3_512 0x43C40000
	#define MS2XL_BASEADDR_PUF_1	0x43C50000
	#define MS2XL_BASEADDR_PUF_2	0x43C60000
#endif

#endif // ROT_SPIRS_H_INCLUDED