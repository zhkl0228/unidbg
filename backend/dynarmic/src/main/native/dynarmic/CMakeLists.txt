cmake_minimum_required(VERSION 3.12)
project(dynarmic_jni CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(JNI REQUIRED)

set(DYNARMIC_HOME "/build/dynarmic" CACHE PATH "Path to yuzu-dynarmic source tree")
set(DYNARMIC_BUILD "${DYNARMIC_HOME}/build" CACHE PATH "Path to yuzu-dynarmic build tree")

add_library(dynarmic SHARED
    dynarmic.cpp
    arm_dynarmic_cp15.cpp
)

target_include_directories(dynarmic PRIVATE
    ${DYNARMIC_HOME}/src
    ${DYNARMIC_HOME}/externals/fmt/include
    ${JNI_INCLUDE_DIRS}
)

target_compile_definitions(dynarmic PRIVATE DYNARMIC_MASTER)
target_compile_options(dynarmic PRIVATE -O2)

target_link_libraries(dynarmic PRIVATE
    ${DYNARMIC_BUILD}/src/dynarmic/libdynarmic.a
    ${DYNARMIC_BUILD}/externals/mcl/src/libmcl.a
    ${DYNARMIC_BUILD}/externals/fmt/libfmt.a
    ${DYNARMIC_BUILD}/externals/zydis/libZydis.a
)
