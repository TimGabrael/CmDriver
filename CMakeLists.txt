cmake_minimum_required(VERSION 3.15)

project(kerpg)
set_property(GLOBAL PROPERTY USER_FOLDERS ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /WX")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/FindWDK/cmake")
find_package(WDK REQUIRED)

wdk_add_driver(cmdriver src/driver.c src/driver.h)
add_executable(user_app src/main.cpp src/driver.h)
add_executable(target_app src/target.cpp)
