cmake_minimum_required(VERSION 2.8.12)
project(kvm C)

find_package(JNI REQUIRED)

add_library(kvm SHARED kvm.c)

target_include_directories(kvm PRIVATE
    ${CMAKE_SOURCE_DIR}/linux-headers
    ${JNI_INCLUDE_DIRS}
)

target_compile_options(kvm PRIVATE -std=gnu99 -O2)
