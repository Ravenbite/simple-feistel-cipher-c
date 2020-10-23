#pragma once
#include <stdint.h>


/* sbox size */
typedef enum SBOX_CONSTANTS {
	SBOX_SIZE_UINT = 256,
	SBOX_ELEMENTS = 256, 
	SBOX_INPUT_SIZE_UINT = 1,
	SBOX_OUTPUT_SIZE_UINT = 1,
};

/* compute sbox */
void sbox_compute(uint8_t p_sbox[SBOX_SIZE_UINT]);