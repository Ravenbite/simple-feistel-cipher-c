#include "n_aux_math.h"
#include <time.h>
#include <stdio.h>
// very simple random number generator 
void aux_naiv_rng(uint8_t* dst, size_t dst_size, size_t generate)
{
	time_t t;

	if (dst_size < generate)
		return

		srand((unsigned)time(&t));

	for (int i = 0; i < generate; i++)
	{
		dst[i] = (uint8_t)rand();
	}
}

// print memory dst on screen till next \0 as hex representation
void aux_print_array_as_hex(uint8_t* dst, size_t size)
{
	printf("0x");
	for (int i = 0; i < size; i++)
	{
		if (dst[i] == 0x00)
			printf("00");
		else
			printf("%x", dst[i] & 0xff);
	}
	printf("\n");
}

void aux_xor_uint8_2way(uint8_t* dst, uint8_t* src, size_t size)
{
	for (int i = 0; i < size; i++)
	{
		dst[i] ^= src[i];
	}
}

void aux_xor_uint8_3way(uint8_t* dst, uint8_t* src1, uint8_t* src2, size_t size)
{
	for (int i = 0; i < size; i++)
	{
		dst[i] = src1[i] ^ src2[i];
	}
}


void conceal_memory_content(aux__conceal_memory_task* task)
{
	if (task->masked == TRUE)
		return;

	aux_xor_uint8_2way(task->dst_size, task->buf_size, task->dst_size);
	task->masked = TRUE;
}

void unconceal_memory_content(aux__conceal_memory_task* task)
{
	if (task->masked == FALSE)
		return;

	aux_xor_uint8_2way(task->p_dst, task->p_buf, task->dst_size);
	task->masked = FALSE;
}

void unconceal_memory_content_copy(aux__conceal_memory_task* task, uint8_t* copy)
{
	if (task->masked == FALSE)
		return;

	aux_xor_uint8_2way(copy, task->p_buf, task->dst_size);
}

aux__MEMORY_CONCEALMENT_STATE get_memory_concealment_state(aux__conceal_memory_task* task)
{
	aux__MEMORY_CONCEALMENT_STATE result;
	
	if (task->masked == TRUE)
		result = MEMORY_CONCEALED;
	else
		result = MEMORY_UNCONCEALED;
	return result;
}

aux__BLOCK_UINT aux_get_BLOCK_UINT(aux__BLOCK_MODI mode)
{
	switch (mode)
	{
	case BLOCK_128_MODI:
		return BLOCK_128_UINT;
		break;
	case BLOCK_256_MODI:
		return BLOCK_256_UINT;
		break;
	case BLOCK_512_MODI:
		return BLOCK_512_UINT;
		break;
	default:
		return -1;
		break;
	}
}

aux__BLOCK_BIT aux_get_BLOCK_BIT(aux__BLOCK_MODI mode)
{
	switch (mode)
	{
	case BLOCK_128_MODI:
		return BLOCK_128_BIT;
		break;
	case BLOCK_256_MODI:
		return BLOCK_256_BIT;
		break;
	case BLOCK_512_MODI:
		return BLOCK_512_BIT;
		break;
	default:
		return -1;
		break;
	}
}
