cmake_minimum_required(VERSION 2.8.12)
project(unicorn_jni C)

find_package(JNI REQUIRED)

set(UNICORN_HOME "/build/unicorn" CACHE PATH "Path to unicorn source tree")
set(UNICORN_BUILD "${UNICORN_HOME}/build" CACHE PATH "Path to unicorn build tree")

add_library(unicorn SHARED
    unicorn.c
    sample_arm.c
    sample_arm64.c
)

target_include_directories(unicorn PRIVATE
    ${UNICORN_HOME}/include
    ${JNI_INCLUDE_DIRS}
)

target_compile_options(unicorn PRIVATE -O3 -DNDEBUG)

target_link_libraries(unicorn PRIVATE
    ${UNICORN_BUILD}/libunicorn.a
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(unicorn PRIVATE rt)
endif()
