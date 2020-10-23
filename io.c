#include "io.h"
#include "n_aux_math.h"
#include <errno.h>
#include <Windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/locking.h>
#include <share.h>
#include <fcntl.h>

// void(*callback_on_error)(char*, int)
bool io__error_dispatcher(errno_t error, void(*callback_on_error)(char*, int))
{
    if (!callback_on_error == 0)
        return error;

    switch (error)
    {
    case EACCES:
        callback_on_error("The given path is a directory, or the file is read-only, but an open-for-writing operation was attempted.", error);
        break;
    case EEXIST:
        callback_on_error("_O_CREAT and _O_EXCL flags were specified, but filename already exists.", error);
        break;
    case EINVAL:
        callback_on_error("Invalid oflag, shflag, or pmode argument, or pfh or filename was a null pointer.", error);
        break;
    case EMFILE:
        callback_on_error("No more file descriptors available.", error);
        break;
    case ENOENT:
        callback_on_error("File or path not found.", error);
        break;
    case EBADF:
        callback_on_error("Parameter validation failed.", error);
        break;
    default:
        callback_on_error("Unknown error.", error);
        break;
    }

    return error;
}

bool io__crt_sopen_s(int* fd, char* file_path, int open_flags, int share_flags, int perm, void(*callback_on_error)(char*, int))
{
    errno_t result = _sopen_s(fd, file_path, open_flags, share_flags, perm);
    
    if (result == 0)
        return TRUE;
    else
        return io__error_dispatcher(result, callback_on_error);
}

bool io__crt_close(int* fd, void(*callback_on_error)(char*, int))
{
    errno_t result = _close(*fd);

    if (result == -1)
        return io__error_dispatcher(EBADF, callback_on_error);
    else
        return TRUE;
}

bool io__crt_check_file(char* filePath, void(*callback_on_error)(char*, int))
{
   errno_t result = _access_s(filePath, 06);  
    
   if (result == 0)
       return TRUE;
   else
       return io__error_dispatcher(result, callback_on_error);
}

bool io__crt_extend_file(char* filePath, size_t increase_by, void(*callback_on_error)(char*, int))
{
    int fd; const char buf = '\0'; const void* p_buf = &buf;
    io__crt_sopen_s(&fd, filePath, O_WRONLY | _O_APPEND, _SH_DENYWR, _S_IREAD, callback_on_error);
    
    for (size_t i = 0; i < increase_by; i++)
    {
        _write(fd, p_buf, 1);
    }
    
    io__crt_close(&fd, callback_on_error);
    return TRUE;
}

size_t io__crt_get_file_size(char* filePath, void(*callback_on_error)(char*, int))
{
    int fd; size_t filesize;
    io__crt_sopen_s(&fd, filePath, O_RDONLY, _SH_DENYNO, _S_IREAD, callback_on_error);
    filesize = (size_t)_filelength(fd);
    io__crt_close(&fd, callback_on_error);
    return filesize;
}

/* -------------------------------------------------------------------------------------------------- */

HANDLE io__win32_create_handle(char* file_path, long open_flags)        // GENERIC_WRITE
{
    HANDLE file_handle;
    file_handle = CreateFileA((LPCSTR)file_path, open_flags, 0, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    return file_handle;
}

DWORD io__win32_write_to_handle(HANDLE file_handle, void* data, size_t size)
{
    DWORD bytes_written;
    WriteFile(file_handle, (LPCVOID)data, (DWORD)size, &bytes_written, NULL);
    return bytes_written;
}

long long int io__win32_allocate_file_space(HANDLE file_handle, size_t size)
{
    FILE_ALLOCATION_INFO file_info;
    file_info.AllocationSize.QuadPart = (long long int) size;
    SetFileInformationByHandle(file_handle, FileAllocationInfo, &file_info, sizeof(file_info));
    return file_info.AllocationSize.QuadPart;
}

long long int io__win32_get_file_size(HANDLE file_handle)
{
    LARGE_INTEGER x;
    if (!GetFileSizeEx(file_handle, &x))
        return -1;
    else
        return x.QuadPart;
}

bool io__win32_truncate_file(HANDLE file_handle, size_t new_size)
{
    SetFilePointer(file_handle, (long)new_size, NULL, FILE_BEGIN);
    SetEndOfFile(file_handle);
}

io__mmap_state* io__win32_memory_mapping(char* file_path,void(*callback_on_error)(char*, int))
{
    int win32_exitcode;
    io__mmap_state* state = (io__mmap_state*)calloc(1, sizeof(io__mmap_state));

    state->file_handle = io__win32_create_handle(file_path, GENERIC_READ | GENERIC_WRITE);
    if (state->file_handle == INVALID_HANDLE_VALUE)
        goto failed;
    
    state->map_handle = CreateFileMappingA(state->file_handle, NULL, PAGE_READWRITE | SEC_RESERVE, 0, 0, 0);
    if (state->map_handle == NULL)
        goto failed;

    state->map_view = MapViewOfFile(state->map_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (state->map_view == NULL)
        goto failed;
    

    return state;

failed:
    win32_exitcode = GetLastError();
    CloseHandle(state->file_handle);
    CloseHandle(state->map_handle);

    if (callback_on_error != 0)
        callback_on_error("io_win32_memory_mapping fault. Lookup exitcode for more.", win32_exitcode);

    return NULL;
}

HANDLE io__win32_file_map(HANDLE file_handle,void(*callback_on_error)(char*, int))
{
    int exit_code;
    HANDLE map_handle;
    
    map_handle = CreateFileMappingA(file_handle, NULL, PAGE_READWRITE | SEC_RESERVE, 0, 0, 0);
    if (map_handle == NULL)
    {
        exit_code = GetLastError();

        if (callback_on_error != 0)
            callback_on_error("io_win32_memory_mapping fault. Lookup exitcode for more.", exit_code);
        else
            return INVALID_HANDLE_VALUE;
    }

    return map_handle;
}



void io__win32_unmap_and_close_file(HANDLE file_handle, HANDLE map_handle, void* map_view)
{
    map_view = NULL;
    CloseHandle(map_handle);
    CloseHandle(file_handle);
}
