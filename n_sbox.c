#include "n_sbox.h"
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

void sbox_compute(uint8_t p_sbox[SBOX_SIZE_UINT])
{
	/* 
		Following code has been copy pasted and therefore is'nt from myself =)
		https://en.wikipedia.org/wiki/Rijndael_S-box
	*/

	uint8_t p = 1, q = 1;

	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
		p_sbox[p] = xformed ^ 0x63;

	} while (p != 1);
	
	
	/* 0 is a special case since it has no inverse */
	p_sbox[0] = 0x63;
}


