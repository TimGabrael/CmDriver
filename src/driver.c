#include "driver.h"
#include <ntdef.h>
#include <ntifs.h>
#include <intrin.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <stdbool.h>

// wowx
#define POOL_TAG 0x776F7778
#define KERR(txt, ...) DbgPrintEx(0, 0, txt, __VA_ARGS__);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;

#pragma pack(push, 1)
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	UINT8 Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	ULONG Reserved2;
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved4;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved5;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved6;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved7;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved8[6];
} SYSTEM_PROCESS_INFORMATION;
#pragma pack(pop)



NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T NumberOfBytesCopied);
PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
PVOID NTAPI PsGetProcessPeb(PEPROCESS process);
PVOID NTAPI RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)


void* GetSystemModuleBase(const char* module_name) {
    ULONG bytes = 0;
    void* module_base = NULL;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0) {
        KERR("[GetSystemModuleBase]: Failed to QuerySystemInformation\n");
        return NULL;
    }
    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolZero(NonPagedPool, bytes, POOL_TAG);
    if (!modules) {
        KERR("[GetSystemModuleBase]: Failed to allocate pool with tag\n");
        return NULL;
    }
    status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
    if (!NT_SUCCESS(status)) {
        KERR("[GetSystemModuleBase]: Failed to QuerySystemInformation 2\n");
        goto cleanup_modules;
    }
    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        if (strncmp((const char*)modules->Modules[i].FullPathName, module_name, sizeof(modules->Modules[i].FullPathName)) == 0) {
            module_base = modules->Modules[i].ImageBase;
            break;
        }
    }
cleanup_modules:
    ExFreePoolWithTag((PVOID)modules, POOL_TAG);
    return module_base;
}
void* GetSystemModuleExport(const char* module_name, PCCH routine_name) {
    void* pmodule = GetSystemModuleBase(module_name);
    if (!pmodule) {
        KERR("[GetSystemModuleExport]: Failed to GetSystemModuleBase\n");
        return NULL;
    }
    return RtlFindExportedRoutineByName(pmodule, routine_name);
}
NTSTATUS WriteKernelMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size) {
    if (!address || !buffer || size == 0) {
        return STATUS_FAIL_CHECK;
    }
    SIZE_T bytes = 0;
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return MmCopyVirtualMemory(PsGetCurrentProcess(), address, process, buffer, size, KernelMode, &bytes);
}
bool WriteToReadOnlyMemory(void* address, void* buffer, ULONG size) {
    PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    if (!mdl) {
        KERR("[WriteToReadOnlyMemory]: Failed IoAllocateMdl\n");
        return false;
    }
    bool succeeded = true;

    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mapping) {
        KERR("[WriteToReadOnlyMemory]: Failed MmMapLockedPagesSpecifyCache\n");
        succeeded = false;
        goto cleanup_write_to_read;
    }
    NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        KERR("[WriteToReadOnlyMemory]: Failed MmProtectMdlSystemAddress\n");
        succeeded = false;
        goto cleanup_write_to_read;
    }
    RtlCopyMemory(mapping, buffer, size);


cleanup_write_to_read:
    if (mapping) {
        MmUnmapLockedPages(mapping, mdl);
    }
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return succeeded;
}

// POC for executing code in the kernel
//NTSTATUS CreateAndExecute(void) {
//    UINT8 executable_code[] = {
//        0x90, 0xC3
//    };
//    PVOID pMemory = ExAllocatePoolZero(NonPagedPool, sizeof(executable_code), POOL_TAG);
//    if (!pMemory) {
//        KERR("[CreateAndExecute]: Failed to Allocate Pool with Tag\n");
//        return STATUS_INSUFFICIENT_RESOURCES;
//    }
//    RtlCopyMemory(pMemory, executable_code, sizeof(executable_code));
//
//    void(*pfunc)() = (void(*)())pMemory;
//    pfunc();
//
//    ExFreePoolWithTag(pMemory, POOL_TAG);
//    return STATUS_SUCCESS;
//}

NTSTATUS ReadProcessMemory(uint64_t pid, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) {
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
    if(!NT_SUCCESS(status)) {
        return status;
    }
    status = MmCopyVirtualMemory(process, address, PsGetCurrentProcess(), buffer, size, KernelMode, read);
    return status;
}
NTSTATUS WriteProcessMemory(uint64_t pid, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* write) {
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
    if(!NT_SUCCESS(status)) {
        return status;
    }
    status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer, process, address, size, KernelMode, write);
    return status;
}
NTSTATUS GetProcessIdByName(const wchar_t* name, uint64_t* pid) {
	ULONG mem_needed = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &mem_needed);
	if (!NT_SUCCESS(status) && mem_needed == 0) {
		KERR("NtQuerySystemInformation(ReturnLength: %lu) failed with 0x%X\n", mem_needed, status);
		return status;
	}
    mem_needed += 16 * sizeof(SYSTEM_PROCESS_INFORMATION);
	SYSTEM_PROCESS_INFORMATION* sysinfo = MmAllocateNonCachedMemory(mem_needed);
	if (sysinfo == NULL) {
		return STATUS_NO_MEMORY;
	}
	status = ZwQuerySystemInformation(SystemProcessInformation, sysinfo, mem_needed, NULL);
	if (!NT_SUCCESS(status)) {
		KERR("NtQuerySystemInformation(SystemInformationLength: %lu) failed with 0x%X\n", mem_needed, status);
		goto free_memory;
	}
    status = STATUS_UNSUCCESSFUL;
	SYSTEM_PROCESS_INFORMATION* cur_proc = sysinfo;
	while (cur_proc->NextEntryOffset > 0) {
		cur_proc = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)cur_proc + cur_proc->NextEntryOffset);
        if(cur_proc->ImageName.Buffer && wcscmp(cur_proc->ImageName.Buffer, name) == 0) {
            *pid = (uint64_t)cur_proc->UniqueProcessId;
            status = STATUS_SUCCESS;
            break;
        }
	}

free_memory:
	MmFreeNonCachedMemory(sysinfo, mem_needed);
	return status;
}
NTSTATUS FindModuleBase(uint64_t process_id, const wchar_t* module_name, PDRIVER_MODULE_BASE output) {
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)process_id, &process);
    if(!NT_SUCCESS(status)) {
        return status;
    }
    KAPC_STATE apc_state;
    KeStackAttachProcess((PRKPROCESS)process, &apc_state);
    uint32_t wait_count = 0;
    if(PsGetProcessWow64Process(process) != NULL) {
        PPEB32 peb = (PPEB32)PsGetProcessWow64Process(process);
        PPEB_LDR_DATA32 ldr = (PPEB_LDR_DATA32)(uintptr_t)peb->Ldr;
        if(!ldr) {
            KERR("[FindModuleBase]: PPEB32 Ldr not found!\n");
            status = STATUS_UNSUCCESSFUL;
            goto finish_find_module_base;
        }
        if(!ldr->Initialized) {
            while(!ldr->Initialized && wait_count++ < 4) {
                LARGE_INTEGER wait = {.QuadPart = -2500 };
                KeDelayExecutionThread(KernelMode, TRUE, &wait);
            }
            if(!ldr->Initialized) {
                KERR("[FindModuleBase]: Ldr not Initialized!\n");
                status = STATUS_UNSUCCESSFUL;
                goto finish_find_module_base;
            }
        }
        status = STATUS_UNSUCCESSFUL;
        for(PLIST_ENTRY32 list_entry = (PLIST_ENTRY32)(uintptr_t)ldr->InLoadOrderModuleList.Flink; list_entry != &ldr->InLoadOrderModuleList; list_entry = (PLIST_ENTRY32)(uintptr_t)list_entry->Flink) {
            PLDR_DATA_TABLE_ENTRY32 ldr_entry32 = CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
            PWCH name = (PWCH)(uintptr_t)ldr_entry32->BaseDllName.Buffer;
            if(name && wcscmp(name, module_name) == 0) {
                output->module_base_ptr = (uint64_t)ldr_entry32->DllBase;
                output->module_size = (uint64_t)ldr_entry32->SizeOfImage;
                status = STATUS_SUCCESS;
                goto finish_find_module_base;
            }
        }

    }
    else {
        PPEB peb = (PPEB)PsGetProcessPeb(process);
        PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)(uintptr_t)peb->Ldr;
        if(!ldr) {
            KERR("[FindModuleBase]: PPEB32 Ldr not found!\n");
            status = STATUS_UNSUCCESSFUL;
            goto finish_find_module_base;
        }
        if(!ldr->Initialized) {
            while(!ldr->Initialized && wait_count++ < 4) {
                LARGE_INTEGER wait = {.QuadPart = -2500 };
                KeDelayExecutionThread(KernelMode, TRUE, &wait);
            }
            if(!ldr->Initialized) {
                KERR("[FindModuleBase]: Ldr not Initialized!\n");
                status = STATUS_UNSUCCESSFUL;
                goto finish_find_module_base;
            }
        }
        status = STATUS_UNSUCCESSFUL;
        for(PLIST_ENTRY list_entry = (PLIST_ENTRY)(uintptr_t)ldr->InLoadOrderModuleList.Flink; list_entry != &ldr->InLoadOrderModuleList; list_entry = (PLIST_ENTRY)(uintptr_t)list_entry->Flink) {
            PLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            PWCH name = (PWCH)(uintptr_t)ldr_entry->BaseDllName.Buffer;
            if(name && wcscmp(name, module_name) == 0) {
                output->module_base_ptr = (uint64_t)ldr_entry->DllBase;
                output->module_size = (uint64_t)ldr_entry->SizeOfImage;
                status = STATUS_SUCCESS;
                goto finish_find_module_base;
            }
        }
    }

finish_find_module_base:
    KeUnstackDetachProcess(&apc_state);
    return status;
}


wchar_t* AllocProcessString(PEPROCESS process, uint64_t str_ptr, uint64_t str_len) {
    wchar_t* str_buffer = (wchar_t*)ExAllocatePoolZero(NonPagedPool, 2* str_len + 2, POOL_TAG);
    if(!str_buffer) {
        KERR("[LoadProcessString]: ExAllocatePoolZero Failed!\n");
        return NULL;
    }
    SIZE_T read_size = 0;
    NTSTATUS status = MmCopyVirtualMemory(process, (PVOID)str_ptr, PsGetCurrentProcess(), str_buffer, 2 * str_len, KernelMode, &read_size);
    if(!NT_SUCCESS(status) || read_size != (2 * str_len)) {
        KERR("[LoadProcessString]: Failed to Copy Memory!\n");
        ExFreePoolWithTag((PVOID)str_buffer, POOL_TAG);
        return NULL;
    }
    str_buffer[str_len] = '\0';
    return str_buffer;
}
void FreeProcessString(wchar_t* str_buffer) {
    if(str_buffer) {
        ExFreePoolWithTag((PVOID)str_buffer, POOL_TAG);
    }
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID io_buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG input_length = irp_stack->Parameters.DeviceIoControl.InputBufferLength;

    if(irp_stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        ULONG io_control_code = irp_stack->Parameters.DeviceIoControl.IoControlCode;
        if(io_control_code == IOCTL_DRIVER_COPY_MEMORY && input_length == sizeof(DRIVER_COPY_MEMORY)) {
            PDRIVER_COPY_MEMORY io_buf = (PDRIVER_COPY_MEMORY)io_buffer;
            SIZE_T read_write;
            if(io_buf->is_write) {
                Irp->IoStatus.Status = WriteProcessMemory(io_buf->process_id, (PVOID)io_buf->target, (PVOID)io_buf->source, io_buf->size, &read_write);
            }
            else {
                Irp->IoStatus.Status = ReadProcessMemory(io_buf->process_id, (PVOID)io_buf->target, (PVOID)io_buf->source, io_buf->size, &read_write);
            }
        }
        else if(io_control_code == IOCTL_DRIVER_GET_PROCESS_ID && input_length == sizeof(DRIVER_GET_PROCESS)) {
            PDRIVER_GET_PROCESS io_buf = (PDRIVER_GET_PROCESS)io_buffer;
            PEPROCESS irp_process = IoGetRequestorProcess(Irp);
            if(irp_process) {
                wchar_t* name_buffer = AllocProcessString(irp_process, io_buf->image_name_ptr, io_buf->image_name_length);
                if(name_buffer) {
                    uint64_t process_id = 0;
                    Irp->IoStatus.Status = GetProcessIdByName(name_buffer, &process_id);
                    if(NT_SUCCESS(Irp->IoStatus.Status)) {
                        PDRIVER_PROCESS driver_process = (PDRIVER_PROCESS)io_buffer;
                        driver_process->process_id = process_id;
                        Irp->IoStatus.Information = sizeof(DRIVER_GET_PROCESS);
                    }
                }
                else {
                    Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
                }
                FreeProcessString(name_buffer);
            }
            if(!NT_SUCCESS(Irp->IoStatus.Status)) {
                PDRIVER_PROCESS driver_process = (PDRIVER_PROCESS)io_buffer;
                driver_process->process_id = 0;
            }
        }
        else if(io_control_code == IOCTL_DRIVER_GET_MODULE_BASE && input_length == sizeof(DRIVER_GET_MODULE_BASE)) {
            PDRIVER_GET_MODULE_BASE io_buf = (PDRIVER_GET_MODULE_BASE)io_buffer;
            PEPROCESS irp_process = IoGetRequestorProcess(Irp);
            if(irp_process) {
                wchar_t* module_name = AllocProcessString(irp_process, io_buf->module_base_name_ptr, io_buf->module_base_name_length);
                if(module_name) {
                    PDRIVER_MODULE_BASE output = (PDRIVER_MODULE_BASE)io_buffer;
                    Irp->IoStatus.Status = FindModuleBase(io_buf->process_id, module_name, output);
                    if(NT_SUCCESS(Irp->IoStatus.Status)) {
                        Irp->IoStatus.Information = sizeof(DRIVER_MODULE_BASE);
                    }
                }
                else {
                    Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
                }
                FreeProcessString(module_name);
            }
        }
        else {
            Irp->IoStatus.Status = STATUS_FAIL_CHECK;
        }
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}
void DriverUnload(PDRIVER_OBJECT DriverObject) {
    NTSTATUS status;
    UNICODE_STRING driver_dos_device_name;
    status = RtlUnicodeStringInit(&driver_dos_device_name, DRIVER_DOS_DEVICE_NAME);
    if(NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&driver_dos_device_name);
    }
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    KERR("[DriverUnload]: Unloaded Custom Driver!\n");
}
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    PDEVICE_OBJECT device_object;
    NTSTATUS status;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
    DriverObject->DriverUnload = DriverUnload;

    UNICODE_STRING driver_device_name;
    UNICODE_STRING driver_dos_device_name;

    status = RtlUnicodeStringInit(&driver_device_name, DRIVER_DEVICE_NAME);
    if(!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlUnicodeStringInit(&driver_dos_device_name, DRIVER_DOS_DEVICE_NAME);
    if(!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateDevice(DriverObject, 0, &driver_device_name, DRIVER_DEVICE_TYPE, 0, FALSE, &device_object);
    if (!NT_SUCCESS(status)) {
        KERR("[DriverEntry]: Failed to Load Driver!\n");
        return status;
    }

    status = IoCreateSymbolicLink(&driver_dos_device_name, &driver_device_name);
    if(!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
    }
    KERR("[DriverEntry]: Loaded Driver!");
    return status;
}
