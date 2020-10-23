#include "n_blockCipher_A.h"
#include "n_sbox.h"
#include "sha_256.h"
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>

void* blockCipher_A_init(size_t feistelRounds, aux__BLOCK_MODI mode, aux__conceal_memory_task* masterKey, aux__conceal_memory_task* salt)
{
	blockCipher_A_state* state = (blockCipher_A_state*)calloc(1, sizeof(blockCipher_A_state));

	memset(state, 0x00, sizeof state);
	sbox_compute( &state->sbox );

	state->operation_state.blockmode = mode;
	state->operation_state.blockuint = aux_get_BLOCK_UINT(mode);
	state->operation_state.feistel_rounds = feistelRounds;

	state->derivation_state.salt = salt;
	state->derivation_state.masterKey = masterKey;
	state->derivation_state.cntr = 0x00;
	state->derivation_state.derived_key_material_size = state->operation_state.feistel_rounds * state->operation_state.blockuint;
	state->derivation_state.first_hash_size = masterKey->dst_size + salt->dst_size + sizeof( size_t);
	state->derivation_state.cntr_offset = masterKey->dst_size + salt->dst_size;
	state->derivation_state.p_derived_key_material = (uint8_t*)calloc(state->derivation_state.derived_key_material_size, sizeof(uint8_t));
	state->derivation_state.p_first_hash = (uint8_t*)calloc(state->derivation_state.first_hash_size, sizeof(uint8_t));

	state->calculation_state.register_buf = (uint8_t*)calloc(state->operation_state.blockuint >> 1, sizeof(uint8_t));
	state->calculation_state.register_left = (uint8_t*)calloc(state->operation_state.blockuint >> 1, sizeof(uint8_t));
	state->calculation_state.register_right = (uint8_t*)calloc(state->operation_state.blockuint >> 1, sizeof(uint8_t));

	return state;
}

void bC_A_derivation(bC_A__keyDerivation_state* state)
{
	uint8_t round_hash[32];
	uint8_t* hash_input = state->p_first_hash;
	int i,j;
	state->cntr++;

	memcpy(hash_input, state->masterKey->p_dst, state->masterKey->dst_size);
	memcpy(hash_input+state->masterKey->dst_size, state->salt->p_dst, state->salt->dst_size );
	memcpy(hash_input+state->cntr_offset, &state->cntr, sizeof(size_t));												

	unconceal_memory_content_copy(state->masterKey, hash_input);
	unconceal_memory_content_copy(state->salt, hash_input + state->masterKey->dst_size);
	
	calc_sha_256(&round_hash, hash_input, state->first_hash_size);
	RtlSecureZeroMemory((PVOID)hash_input, state->first_hash_size);
	
	for (i = 0; i < state->derived_key_material_size; i += 32)
	{
		calc_sha_256(&round_hash, &round_hash, 32);
		memcpy(state->p_derived_key_material + i, &round_hash, 32);
	}

	j = state->derived_key_material_size - i;
	if (j != 0)
	{
		calc_sha_256(&round_hash, &round_hash, 32);
		memcpy(state->p_derived_key_material + i, &round_hash, j);
	}
}

void blockCipher_A_encrypt(blockCipher_A_state* state, uint8_t* inputBlock)
{
	aux__BLOCK_UINT block_size = state->operation_state.blockuint;
	aux__BLOCK_UINT reg_size = state->operation_state.blockuint >> 1;
	int a, b;
	uint8_t* reg_left = state->calculation_state.register_left;
	uint8_t* reg_right = state->calculation_state.register_right;
	uint8_t* reg_buf = state->calculation_state.register_buf;
	uint8_t* reg_key = state->derivation_state.p_derived_key_material;

	memcpy(reg_left, inputBlock + reg_size, reg_size);
	memcpy(reg_right, inputBlock, reg_size);
	memset(reg_buf, 0x00, reg_size);

	bC_A_derivation(&state->derivation_state);

	for (a = 0; a < state->operation_state.feistel_rounds; a++)
	{
		for (b = 0; b < reg_size; b++)
		{
			reg_buf[b] = reg_left[b] ^ *reg_key;
			reg_buf[b] = state->sbox[reg_buf[b]];
			reg_right[b] ^= reg_buf[b];
			reg_key++;
		}

		for (b = 0; b < reg_size; b++)
		{
			reg_buf[b] = reg_right[b] ^ *reg_key;
			reg_buf[b] = state->sbox[reg_buf[b]];
			reg_left[b] ^= reg_buf[b];
			reg_key++;
		}
	}
	memcpy(inputBlock, reg_left, reg_size);
	memcpy(inputBlock + reg_size, reg_right, reg_size);
}
