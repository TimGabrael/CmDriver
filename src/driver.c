#include "driver.h"
#include <ntdef.h>
#include <ntifs.h>
#include <intrin.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <stdbool.h>


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

NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T NumberOfBytesCopied);
PVOID NTAPI RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)


void* GetSystemModuleBase(const char* module_name) {
    ULONG bytes = 0;
    const ULONG pool_tag = 0x776F7778; // wowx
    void* module_base = NULL;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0) {
        DbgPrintEx(0, 0, "[GetSystemModuleBase]: Failed to QuerySystemInformation\n");
        return NULL;
    }
    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolZero(NonPagedPool, bytes, pool_tag);
    if (!modules) {
        DbgPrintEx(0, 0, "[GetSystemModuleBase]: Failed to allocate pool with tag\n");
        return NULL;
    }
    status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "[GetSystemModuleBase]: Failed to QuerySystemInformation 2\n");
        goto cleanup_modules;
    }
    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        if (strncmp((const char*)modules->Modules[i].FullPathName, module_name, sizeof(modules->Modules[i].FullPathName)) == 0) {
            module_base = modules->Modules[i].ImageBase;
            break;
        }
    }
cleanup_modules:
    ExFreePoolWithTag((PVOID)modules, pool_tag);
    return module_base;
}
void* GetSystemModuleExport(const char* module_name, PCCH routine_name) {
    void* pmodule = GetSystemModuleBase(module_name);
    if (!pmodule) {
        DbgPrintEx(0, 0, "[GetSystemModuleExport]: Failed to GetSystemModuleBase\n");
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
        DbgPrintEx(0, 0, "[WriteToReadOnlyMemory]: Failed IoAllocateMdl\n");
        return false;
    }
    bool succeeded = true;

    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mapping) {
        DbgPrintEx(0, 0, "[WriteToReadOnlyMemory]: Failed MmMapLockedPagesSpecifyCache\n");
        succeeded = false;
        goto cleanup_write_to_read;
    }
    NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "[WriteToReadOnlyMemory]: Failed MmProtectMdlSystemAddress\n");
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
//    const ULONG pool_tag = 0x776F7778; // wowx
//    PVOID pMemory = ExAllocatePoolZero(NonPagedPool, sizeof(executable_code), pool_tag);
//    if (!pMemory) {
//        DbgPrintEx(0, 0, "[CreateAndExecute]: Failed to Allocate Pool with Tag\n");
//        return STATUS_INSUFFICIENT_RESOURCES;
//    }
//    RtlCopyMemory(pMemory, executable_code, sizeof(executable_code));
//
//    void(*pfunc)() = (void(*)())pMemory;
//    pfunc();
//
//    ExFreePoolWithTag(pMemory, pool_tag);
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


NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID io_buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG input_length = irp_stack->Parameters.DeviceIoControl.InputBufferLength;

    if(irp_stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        ULONG io_control_code = irp_stack->Parameters.DeviceIoControl.IoControlCode;
        if(io_control_code == IOCTL_DRIVER_COPY_MEMORY) {
            if(input_length == sizeof(DRIVER_COPY_MEMORY)) {
                PDRIVER_COPY_MEMORY io_buf = (PDRIVER_COPY_MEMORY)io_buffer;
                SIZE_T read_write;
                if(io_buf->is_write) {
                    Irp->IoStatus.Status = WriteProcessMemory(io_buf->process_id, (PVOID)io_buf->target, (PVOID)io_buf->source, io_buf->size, &read_write);
                }
                else {
                    Irp->IoStatus.Status = ReadProcessMemory(io_buf->process_id, (PVOID)io_buf->target, (PVOID)io_buf->source, io_buf->size, &read_write);
                }
            }
            else {
                Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
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
    DbgPrintEx(0, 0, "[DriverUnload]: Unloaded Custom Driver!\n");
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
        DbgPrintEx(0, 0, "[DriverEntry]: Failed to Load Driver!\n");
        return status;
    }

    status = IoCreateSymbolicLink(&driver_dos_device_name, &driver_device_name);
    if(!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
    }
    return status;
}
