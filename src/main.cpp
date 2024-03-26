#include "driver.h"
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>

struct Driver {
    Driver() {
        this->driver_handle = INVALID_HANDLE_VALUE;
        ConnectToDriver();
    }
    ~Driver() {
        if(this->driver_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(this->driver_handle);
        }
    }
    bool ReadProcessMemory(uint64_t pid, void* addr, void* buffer, size_t sz) {
        if(this->ConnectToDriver()) {
            DRIVER_COPY_MEMORY read_info = {};
            read_info.target = (uint64_t)addr;
            read_info.source = (uint64_t)buffer;
            read_info.is_write = false;
            read_info.process_id = pid;
            read_info.size = sz;
            DWORD bytes_returned = 0;
            return DeviceIoControl(this->driver_handle, IOCTL_DRIVER_COPY_MEMORY, &read_info, sizeof(read_info), &read_info, sizeof(read_info), &bytes_returned, nullptr);
        }
        return false;
    }
    bool WriteProcessMemory(uint64_t pid, void* addr, void* buffer, size_t sz) {
        if(this->ConnectToDriver()) {
            DRIVER_COPY_MEMORY write_info = {};
            write_info.target = (uint64_t)buffer;
            write_info.source = (uint64_t)addr;
            write_info.is_write = true;
            write_info.process_id = pid;
            write_info.size = sz;
            DWORD bytes_returned = 0;
            return DeviceIoControl(this->driver_handle, IOCTL_DRIVER_COPY_MEMORY, &write_info, sizeof(write_info), &write_info, sizeof(write_info), &bytes_returned, nullptr);
        }
        return false;
    }
    uint64_t GetProcessId(const wchar_t* name) {
        if(this->ConnectToDriver()) {
            DRIVER_GET_PROCESS get_info = {};
            get_info.image_name_length = wcsnlen_s(name, 255);
            get_info.image_name_ptr = (uint64_t)name;
            DWORD bytes_returned = 0;
            DRIVER_PROCESS process_data;
            if(DeviceIoControl(this->driver_handle, IOCTL_DRIVER_GET_PROCESS_ID, &get_info, sizeof(get_info), &process_data, sizeof(process_data), &bytes_returned, nullptr)) {
                return process_data.process_id;
            }
        }
        return 0;
    }
    uint64_t GetModuleBase(uint64_t process_id, const wchar_t* mod_base) {
        if(this->ConnectToDriver()) {
            DRIVER_GET_MODULE_BASE get_base = {};
            get_base.module_base_name_length = wcsnlen_s(mod_base, 255);
            get_base.module_base_name_ptr = (uint64_t)mod_base;
            get_base.process_id = process_id;
            DWORD bytes_returned = 0;
            DRIVER_MODULE_BASE module_data = {};
            if(DeviceIoControl(this->driver_handle, IOCTL_DRIVER_GET_MODULE_BASE, &get_base, sizeof(get_base), &module_data, sizeof(module_data), &bytes_returned, nullptr)) {
                return module_data.module_base_ptr;
            }
        }
        return 0;
    }

    bool ConnectToDriver() {
        if(this->driver_handle == INVALID_HANDLE_VALUE) {
            this->driver_handle = CreateFileW(DRIVER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
        }
        return this->driver_handle != INVALID_HANDLE_VALUE;
    }
    HANDLE driver_handle;
};

uint64_t GetProcessIdByName(const char* name) {
    size_t name_len = strnlen(name, 100);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
            if (strncmp(entry.szExeFile, name, name_len) == 0) {  
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
                uint64_t process_id = (uint64_t)GetProcessId(hProcess);
                CloseHandle(hProcess);
                return process_id;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}


int main() {
    uint64_t proc_id_real = GetProcessIdByName("target_app.exe");

    Driver driver;
    uint64_t proc_id = driver.GetProcessId(L"target_app.exe");
    std::cout << std::hex << "proc_id: " << proc_id << std::endl;
    uint64_t module_base = driver.GetModuleBase(proc_id_real, L"target_app.exe");
    std::cout << std::hex << "module_base: " << module_base << std::endl;

    //uint32_t cur_value = 100;
    while(true) {
        // the address (void*)0x0C22C8FF820 is probably not correct, change to whatever is seen in the target_app
        //if(driver.WriteProcessMemory(proc_id, (void*)0x0C22C8FF820, (void*)&cur_value, sizeof(uint32_t))) {
        //    std::cout << "yes" << std::endl;
        //}
        //else {
        //    std::cout << "no" << std::endl;
        //}
        //std::cout << "cur_value: " << cur_value << std::endl;
        //cur_value += 1;
        Sleep(1000);
    }
    return 0;
}
