#pragma once
#include "n_aux_math.h"
#include <Windows.h>

typedef struct {
	HANDLE file_handle;
	HANDLE map_handle;
	void* map_view;
} io__mmap_state;

bool	io__crt_sopen_s			(int* fd, char* file_path, int open_flags, int share_flags, int perm, void(*callback_on_error)(char*, int));
bool	io__crt_close			(int* fd, void(*callback_on_error)(char*, int));
bool	io__crt_check_file		(char* filePath, void(*callback_on_error)(char*, int));
bool	io__crt_extend_file		(char* filePath, size_t increase_by, void(*callback_on_error)(char*, int));
size_t	io__crt_get_file_size	(char* filePath, void(*callback_on_error)(char*, int));

HANDLE	io__win32_create_handle		   (char* file_path, long open_flags);
DWORD	io__win32_write_to_handle	   (HANDLE file_handle, void* data, size_t size);
bool	io__win32_truncate_file		   (HANDLE file_handle, size_t new_size);
void	io__win32_unmap_and_close_file (HANDLE file_handle, HANDLE map_handle, void* map_view);

io__mmap_state* io__win32_memory_mapping	(char* file_path, void(*callback_on_error)(char*, int));
long long int io__win32_allocate_file_space (HANDLE file_handle, size_t size);
long long int io__win32_get_file_size		(HANDLE file_handle);

