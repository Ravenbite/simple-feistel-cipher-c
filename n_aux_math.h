#pragma once
#include <stdint.h>

/* For MS-Windows change NT to 1, for unix change to 0 */
#define NT 1

/* For inclusion of debug output set val to 1 */
#define DEBUG 1

/* Min SALT BIT */
#define MIN_SALT_BIT 128

/* Min PW BIT */
#define MIN_KEY_BIT 128

/*  */
typedef enum { FALSE = 0, TRUE } bool;

/* aux::typedefs */

typedef enum {
	ENCRYPT,
	DECRYPT
} aux__CIPHER_OP;

typedef enum {
	BLOCK_128_MODI,
	BLOCK_256_MODI,
	BLOCK_512_MODI,
} aux__BLOCK_MODI;

typedef enum {
	BLOCK_128_UINT = 16,
	BLOCK_256_UINT = 32,
	BLOCK_512_UINT = 64,
} aux__BLOCK_UINT;

typedef enum {
	BLOCK_128_BIT = 128,
	BLOCK_256_BIT = 256,
	BLOCK_512_BIT = 512,
} aux__BLOCK_BIT;

typedef struct {
	bool masked;
	size_t dst_size;
	size_t buf_size;
	uint8_t* p_buf;
	uint8_t* p_dst;
} aux__conceal_memory_task;

typedef enum {
	MEMORY_CONCEALED,
	MEMORY_UNCONCEALED,
} aux__MEMORY_CONCEALMENT_STATE;

typedef enum {
	CIPHER_A,
	CIPHER_B,
	CIPHER_C
} aux__CIPHER_ALGO;

/* 
	aux::interface
*/

/* some functions */
void aux_naiv_rng(uint8_t* dst, size_t dst_size, size_t generate);
void aux_print_array_as_hex(uint8_t* dst, size_t size);
void aux_xor_uint8_2way(uint8_t* dst, uint8_t* src, size_t size);
void aux_xor_uint8_3way(uint8_t* dst, uint8_t* src1, uint8_t* src2, size_t size);

/* memory_concealment */
void conceal_memory_content(aux__conceal_memory_task* task);
void unconceal_memory_content(aux__conceal_memory_task* task);
void unconceal_memory_content_copy(aux__conceal_memory_task* task, uint8_t* copy);
aux__MEMORY_CONCEALMENT_STATE get_memory_concealment_state(aux__conceal_memory_task* task);

/* block_enums related */
aux__BLOCK_UINT aux_get_BLOCK_UINT(aux__BLOCK_MODI mode);
aux__BLOCK_BIT aux_get_BLOCK_BIT(aux__BLOCK_MODI mode);

