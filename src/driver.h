#pragma once

#include <stdint.h>

#define DRIVER_NAME             L"CmDriver"
#define DRIVER_DEVICE_NAME      L"\\Device\\CmDriver"
#define DRIVER_DOS_DEVICE_NAME  L"\\DosDevices\\CmDriver"
#define DRIVER_DEVICE_PATH      L"\\\\.\\CmDriver"
#define DRIVER_DEVICE_TYPE      0x00000022


#define IOCTL_DRIVER_COPY_MEMORY ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS))

typedef struct _DRIVER_COPY_MEMORY {
	uint64_t source;     // source buffer address.
	uint64_t target;     // target buffer address.
	uint64_t size;       // buffer size.
	uint64_t process_id; // target process ID.
	int is_write;        // 1 for writing, 0 for reading
} DRIVER_COPY_MEMORY, *PDRIVER_COPY_MEMORY;

