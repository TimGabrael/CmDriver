#include <iostream>
#include <windows.h>


int main() {
    int value = 0;
    while(true) {
        std::cout << "value: " << value << ", " << &value << std::endl;
        Sleep(1000);
    }
}
