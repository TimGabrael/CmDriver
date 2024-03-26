#pragma once

#include <stdint.h>

#define DRIVER_NAME             L"CmDriver"
#define DRIVER_DEVICE_NAME      L"\\Device\\CmDriver"
#define DRIVER_DOS_DEVICE_NAME  L"\\DosDevices\\CmDriver"
#define DRIVER_DEVICE_PATH      L"\\\\.\\CmDriver"
#define DRIVER_DEVICE_TYPE      0x00000022


#define IOCTL_DRIVER_COPY_MEMORY        ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS))
#define IOCTL_DRIVER_GET_PROCESS_ID     ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS))
#define IOCTL_DRIVER_GET_MODULE_BASE     ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS))

typedef struct _DRIVER_COPY_MEMORY {
	uint64_t source;     // source buffer address.
	uint64_t target;     // target buffer address.
	uint64_t size;       // buffer size.
	uint64_t process_id; // target process ID.
	int is_write;        // 1 for writing, 0 for reading
} DRIVER_COPY_MEMORY, *PDRIVER_COPY_MEMORY;

typedef struct _DRIVER_GET_PROCESS {
    uint64_t image_name_ptr;
    uint64_t image_name_length;
} DRIVER_GET_PROCESS, *PDRIVER_GET_PROCESS;
typedef struct _DRIVER_PROCESS {
    uint64_t process_id;
} DRIVER_PROCESS, *PDRIVER_PROCESS;

typedef struct _DRIVER_GET_MODULE_BASE {
    uint64_t process_id;
    uint64_t module_base_name_ptr;
    uint64_t module_base_name_length;
} DRIVER_GET_MODULE_BASE, *PDRIVER_GET_MODULE_BASE;

typedef struct _DRIVER_MODULE_BASE {
    uint64_t module_base_ptr;
    uint64_t module_size;
} DRIVER_MODULE_BASE, *PDRIVER_MODULE_BASE;

