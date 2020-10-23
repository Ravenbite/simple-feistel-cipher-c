#include "n_cfb_mode_A.h"
#include "n_aux_math.h"
#include "n_blockCipher_A.h"
#include "io.h"
#include <assert.h>

int main(int argc, char** argv)
{





	
	cfb_A__state state;
	aux__conceal_memory_task masterKey;
	aux__conceal_memory_task salt;
	uint8_t pw = "ABCDEFG54321";
	uint8_t saltt = "1234SALT4321";

	masterKey.masked = FALSE;
	masterKey.p_dst = &pw;
	masterKey.dst_size = strlen((char*)&pw);

	salt.masked = FALSE;
	salt.p_dst = &salt;
	salt.dst_size = strlen((char*)&saltt);

	cfb_A__init(&state, &masterKey, &salt, 8, BLOCK_128_MODI, CIPHER_A);
	cfb_A__encrypt_file(&state, "txt.txt");
	

}

void cfb_A__perform_asserts(void)
{
	assert(cfb_A__MAX_VIEW_SIZE >= BLOCK_512_UINT);			// view have to be larger than greatest block size

}

void cfb_A__init(cfb_A__state* state, aux__conceal_memory_task* masterKey, aux__conceal_memory_task* salt, size_t rounds, aux__BLOCK_MODI block_mode, aux__CIPHER_ALGO cipher_algo)
{
	if (!state)
		exit(EXIT_FAILURE);

	state->cipher_state = NULL;
	state->cipher_algo = cipher_algo;
	state->block_mode = block_mode;
	state->block_size_uint8 = aux_get_BLOCK_UINT(block_mode);

	cfb_A__init_io(&state->io_state, salt, salt->dst_size, state->block_size_uint8);
	cfb_A__init_map(&state->map_state);
	cfb_A__init_stream(&state->stream_state, state->block_size_uint8);

	state->cipher_state = (void*)cfb_A__cipher_create[cipher_algo](rounds, block_mode, masterKey, salt);
}

inline void cfb_A__init_map(cfb_A__view_state* map_state)
{
	SYSTEM_INFO SysInfo;	
	GetSystemInfo(&SysInfo);	// get allocation granularity

	map_state->allocationGranularity = SysInfo.dwAllocationGranularity;
	map_state->blocks_inside_view = 0;
	map_state->data_offset_from_view_ptr = 0;
	map_state->data_size = 0;
	map_state->data_start = 0;
	map_state->full_mapping = FALSE;
	map_state->mapped_data_size = 0;
}

inline void cfb_A__init_stream(cfb_A__stream_state* stream_state, size_t block_size)
{
	stream_state->buf1 = (uint8_t*)calloc(block_size, sizeof(uint8_t));
	stream_state->buf2 = (uint8_t*)calloc(block_size, sizeof(uint8_t));
	stream_state->cntr = 0x00;

	aux_naiv_rng(stream_state->buf1, block_size, block_size);
	memcpy(stream_state->buf2, stream_state->buf1, block_size);
}

inline void cfb_A__init_io(cfb_A__io_state* state, aux__conceal_memory_task* salt, size_t salt_size, aux__BLOCK_UINT blockSize)
{
	state->file_handle = INVALID_HANDLE_VALUE;
	state->map_handle = INVALID_HANDLE_VALUE;
	state->file_size = -1;
	state->p_file_path = NULL;
	state->p_mapped = NULL;

	state->cleartext_size = 0;
	state->salt = salt;
	state->salt_size = salt_size;
	state->block_size = blockSize;
	state->padding = 0;
}

void cfb_A__encrypt_file(cfb_A__state* state, char* file_path)
{
	int map_round = 0, last_map_round = 1;


	if (!io__crt_check_file(file_path, 0))
		exit(EXIT_FAILURE);

	// create file handle and get file size
	state->io_state.file_handle = io__win32_create_handle(file_path, GENERIC_READ | GENERIC_WRITE);
	state->io_state.file_size = (size_t)io__win32_get_file_size(state->io_state.file_handle);

	// compute padding and extend file
	cfb_A__extend_file(&state->io_state);
	io__win32_allocate_file_space(state->io_state.file_handle, state->io_state.file_size);

	// force os to extend file, create new handlers, tell OS our plans for mmap the file
	CloseHandle(state->io_state.file_handle);
	state->io_state.file_handle = io__win32_create_handle(file_path, GENERIC_READ | GENERIC_WRITE);
	state->io_state.map_handle = state->io_state.map_handle = CreateFileMappingA(state->io_state.file_handle, NULL, PAGE_READWRITE | SEC_RESERVE, 0, 0, 0);

	// compute max possible view size and how many steps are necessary
	last_map_round = cfb_A__compute_greatest_view_size_rounds(state);
	
	// for each round; create view according to allocation granularity, compute offset, encrypt view / offset, unmap
	for (map_round; map_round < last_map_round; map_round++)
	{
		cfb_A__map_view(state);
		cfb_A__encrypt_view(state);
		cfb_A__unmap_view(state);
	}

	// map metadata located near the end of the file and override allocated file space with metadata
	cfb_A__map_metadata(state);
	cfb_A__write_metadata(state);	
	cfb_A__unmap_view(state);

	// conceal memory, close all dynamic objects, prevent user to use same state again
	//cfb_A__close();
}

// append metadata. Last byte is blockSize, second last is salt size
cfb_A__write_metadata(cfb_A__state* state)
{
	// copy salt if needed and unconceal
	uint8_t* salt_cpy = calloc(state->io_state.salt_size, sizeof(uint8_t));
	memcpy(salt_cpy, state->io_state.salt->p_dst, state->io_state.salt_size);
	if (state->io_state.salt->masked == MEMORY_CONCEALED)
		aux_xor_uint8_2way(salt_cpy, state->io_state.salt->p_buf, state->io_state.salt_size);

	// get dst
	uint8_t* dst = ((uint8_t*)state->io_state.p_mapped) + state->map_state.data_offset_from_view_ptr;
	
	// append salt after cleartext
	memcpy(dst, salt_cpy, state->io_state.salt_size);
	dst += state->io_state.salt_size;

	// append iv after salt
	memcpy(dst, state->stream_state.buf2, state->block_size_uint8);
	dst += state->block_size_uint8;

	// append salt size after iv
	memcpy(dst, &state->io_state.salt_size, sizeof(size_t));
	dst += sizeof(size_t);

	// append block_mode after salt size
	size_t block_mode = state->block_mode;
	memcpy(dst, &block_mode, sizeof(size_t));

	// erase unconcealed salt copy
	RtlSecureZeroMemory((PVOID)salt_cpy, state->io_state.salt_size);
}



void cfb_A__unmap_view(cfb_A__state* state)
{
	UnmapViewOfFile((LPCVOID)state->io_state.p_mapped);
}

void cfb_A__map_metadata(cfb_A__state* state)
{
	DWORD data_start, data_len, data_offset;
	DWORD view_start, view_len;

	// skip
	if (state->map_state.full_mapping == TRUE)	// map full file
		goto fullmap;
	
	// compute view start -- should be nearest multiple of the allocation granularity
	data_len = state->io_state.meta_data_size;
	data_start = state->io_state.meta_data_start;
	view_start = (data_start / state->map_state.allocationGranularity) * state->map_state.allocationGranularity;
	
	// now get the view size, should be greather than data_size
	view_len = (data_start % state->map_state.allocationGranularity) + data_len;

	// now get the offset to our data_start, because the view starts before it
	data_offset = data_start - view_start;

	// map the view that contains at data_offset our desired data part
	state->io_state.p_mapped = MapViewOfFile(state->io_state.map_handle, FILE_MAP_ALL_ACCESS, 0, view_start, view_len);

	// return with results
	state->map_state.data_start = data_start;
	state->map_state.data_size = data_len;
	state->map_state.data_offset_from_view_ptr = data_offset;
	return;
	
	
fullmap:
	state->io_state.p_mapped = MapViewOfFile(state->io_state.map_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	state->map_state.data_start = state->io_state.meta_data_start;
	state->map_state.data_size = state->io_state.meta_data_size;
	state->map_state.data_offset_from_view_ptr = 0;
	return;
}

void cfb_A__encrypt_view(cfb_A__state* state)
{
	// buf and iv hold when executed first time the iv
	size_t block = 0;
	uint8_t* buf = state->stream_state.buf1;
	uint8_t* iv = state->stream_state.buf2;
	uint8_t* data_start = ((uint8_t*)state->io_state.p_mapped + state->map_state.data_offset_from_view_ptr);
	
	//cfb mode
	for (block; block < state->map_state.blocks_inside_view; block++)
	{
		cfb_A__cipher_encrypt[state->cipher_algo](state->cipher_state, buf);
		aux_xor_uint8_2way(data_start, buf, state->block_size_uint8);
		memcpy(buf, data_start, state->block_size_uint8);
		data_start += state->block_size_uint8;
	}
}

void cfb_A__map_view(cfb_A__state* state)
{
	DWORD data_start, data_len, data_offset;
	DWORD view_start, view_len;
	int k = 1;

	// get necessary encrypt calls
	state->map_state.blocks_inside_view = state->map_state.data_size / state->block_size_uint8;

	// skip if we can map the whole file
	if (state->map_state.full_mapping == TRUE)	// map full file
		goto fullmap;
		
	// compute view start -- should be nearest multiple of the allocation granularity
	data_len = state->map_state.data_size;
	data_start = state->map_state.mapped_data_size + state->map_state.mapped_data_size;		
	view_start = (data_start / state->map_state.allocationGranularity) * state->map_state.allocationGranularity;

	// now get the view size, should be greather than data_size
	view_len = (data_start % state->map_state.allocationGranularity) + data_len;

	// now get the offset to our data_start, because the view starts before it
	data_offset = data_start - view_start;

	// map the view that contains at data_offset our desired data part
	state->io_state.p_mapped = MapViewOfFile(state->io_state.map_handle, FILE_MAP_ALL_ACCESS, 0, view_start, view_len);
	
	// return with results
	state->map_state.data_start = data_start;
	state->map_state.data_size = data_len;
	state->map_state.data_offset_from_view_ptr = data_offset;
	state->map_state.mapped_data_size += data_len;
	return;
	
fullmap:
	state->io_state.p_mapped = MapViewOfFile(state->io_state.map_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	state->map_state.mapped_data_size += state->map_state.data_size;
	return;
}

/* compute max view size which is a multiple of blocksize but has to be lower that defined limit */
size_t cfb_A__compute_greatest_view_size_rounds(cfb_A__state* state)
{
	int k = 1;
	size_t max_size = 0, rounds_necessary = 0;

	// get max k | blocksize*k < maxsize
	do
	{
		k++;
	} while ( (state->block_size_uint8 * k) < cfb_A__MAX_VIEW_SIZE );
	max_size = state->block_size_uint8 * k;

	// truncate if needed
	if (max_size > (state->io_state.cleartext_size))
		max_size = state->io_state.cleartext_size;

	// get rounds
	if (max_size = state->io_state.cleartext_size)
	{
		// only one round is needed, skip view logic and map full file because limit is sufficient
		state->map_state.full_mapping = TRUE;
		state->map_state.data_size = max_size;
		return 1;
	}
	else
	{
		// return rounds needed
		state->map_state.data_size = max_size;
		return state->io_state.cleartext_size / max_size;
	}
}

void cfb_A__extend_file(cfb_A__io_state* io_state)
{
	size_t cleartext_padding = io_state->block_size - (io_state->file_size % io_state->block_size);

	io_state->padding = cleartext_padding;															// Block Padding
	io_state->padding += io_state->salt_size;														// Salt
	io_state->padding += io_state->block_size;														// IV
	io_state->padding += 2*sizeof(size_t);															// Helper

	io_state->cleartext_size = io_state->file_size + cleartext_padding;
	io_state->file_size = io_state->cleartext_size + io_state->padding;

	io_state->meta_data_size = io_state->padding - cleartext_padding;
	io_state->meta_data_start = cleartext_padding;
}


