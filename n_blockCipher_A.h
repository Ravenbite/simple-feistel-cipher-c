#pragma once
#include "n_aux_math.h"
#include <stdint.h>

typedef struct {
	uint8_t* p_derived_key_material;
	uint8_t* p_first_hash;
	size_t  derived_key_material_size;
	size_t	first_hash_size;
	size_t  cntr;
	size_t  cntr_offset;
	aux__conceal_memory_task* masterKey;
	aux__conceal_memory_task* salt;
} bC_A__keyDerivation_state;

typedef struct {
	size_t feistel_rounds;
	aux__BLOCK_MODI blockmode;
	aux__BLOCK_UINT blockuint;
} bC_A__operation_state;

typedef struct {
	uint8_t* register_left;
	uint8_t* register_right;
	uint8_t* register_buf;
} bC_A__calculation_state;


typedef struct {
	uint8_t sbox[256];							// 16x16 byte Rijndael S-Box 
	bC_A__keyDerivation_state derivation_state;
	bC_A__operation_state     operation_state;
	bC_A__calculation_state   calculation_state;
} blockCipher_A_state;

void* blockCipher_A_init(size_t feistelRounds, aux__BLOCK_MODI mode, aux__conceal_memory_task* masterKey, aux__conceal_memory_task* salt);
void blockCipher_A_encrypt(blockCipher_A_state* state, uint8_t* block);
void blockCipher_A_close(blockCipher_A_state* state);

void bC_A_derivation(bC_A__keyDerivation_state state);


