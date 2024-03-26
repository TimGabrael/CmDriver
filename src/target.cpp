#include <iostream>
#include <windows.h>


int main() {
    DWORD cur_process_id = GetCurrentProcessId();
    HMODULE module = GetModuleHandleA("target_app.exe");
    std::cout << "cur_process_id: " << std::hex << cur_process_id << std::endl;
    std::cout << "module: " << std::hex << module << std::endl;

    int value = 0;
    while(true) {
        std::cout << "value: " << value << ", " << &value << std::endl;
        Sleep(1000);
    }
}
