#pragma once

#include "n_aux_math.h"
#include "n_blockCipher_A.h"
#include "io.h"
#include <Windows.h>

/* MAX MEMORY MAPPED VIEW SIZE */
#define cfb_A__MAX_VIEW_SIZE 1024*1024

/* typedefs */
typedef struct {
	HANDLE file_handle;
	HANDLE map_handle;
	void* p_mapped;
	char* p_file_path;
	size_t file_size;
	size_t cleartext_size;
	aux__conceal_memory_task* salt;
	size_t salt_size;
	aux__BLOCK_UINT block_size;
	size_t padding;
	size_t meta_data_start;
	size_t meta_data_size;
} cfb_A__io_state;

typedef struct {
	size_t data_start;
	size_t data_size;
	size_t data_offset_from_view_ptr;
	size_t mapped_data_size;
	size_t blocks_inside_view;
	bool   full_mapping;
	DWORD  allocationGranularity;
} cfb_A__view_state;

typedef struct {
	uint8_t* buf1;
	uint8_t* buf2;
	size_t   cntr;
} cfb_A__stream_state;

typedef struct {
	aux__CIPHER_ALGO cipher_algo;
	void* cipher_state;
	aux__BLOCK_MODI block_mode;
	aux__BLOCK_UINT block_size_uint8;
	cfb_A__io_state io_state;
	cfb_A__view_state map_state;
	cfb_A__stream_state stream_state;
} cfb_A__state;


/* prototypes */
void cfb_A__perform_asserts(void);
void cfb_A__init(cfb_A__state* state, aux__conceal_memory_task* masterKey, aux__conceal_memory_task* salt, size_t rounds, aux__BLOCK_MODI block_mode, aux__CIPHER_ALGO cipher_algo);
inline void cfb_A__init_map(cfb_A__view_state* map_state);
inline void cfb_A__init_stream(cfb_A__stream_state* stream_state, size_t block_size);
inline void cfb_A__init_io(cfb_A__io_state* state, aux__conceal_memory_task* salt, size_t salt_size, aux__BLOCK_UINT blockSize);
void cfb_A__encrypt_file(cfb_A__state* state, char* file_path);
cfb_A__write_metadata(cfb_A__state* state);
void cfb_A__unmap_view(cfb_A__state* state);
void cfb_A__map_metadata(cfb_A__state* state);
void cfb_A__encrypt_view(cfb_A__state* state);
void cfb_A__map_view(cfb_A__state* state);
size_t cfb_A__compute_greatest_view_size_rounds(cfb_A__state* state);
void cfb_A__extend_file(cfb_A__io_state* io_state);


/* registered block ciphers for cfb mode
	-- to add more ciphers, simply append function ptr inside {}

	example:	void* cipher_state = cfb_A__cipher_create[CIPHER_A](16, BLOCK_256, masterkey, salt)
								     cfb_A__cipher_encrypt[CIPHER_B](state, data)                       
*/
void* (*cfb_A__cipher_create[])(size_t feistelRounds, aux__BLOCK_MODI blockMode, aux__conceal_memory_task* masterKey, aux__conceal_memory_task* salt) = { blockCipher_A_init };
void (*cfb_A__cipher_encrypt[])(void* state, uint8_t* block) = { blockCipher_A_encrypt };
//void (*cfb_A__cipher_close[])(void* state) = { blockCipher_A_close };


