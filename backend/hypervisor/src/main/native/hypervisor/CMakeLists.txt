cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_SYSTEM_NAME Darwin)
set(PROJECT_LIB_NAME hypervisor)

find_package(JNI REQUIRED)
if (JNI_FOUND)
    message (STATUS "JNI_INCLUDE_DIRS=${JNI_INCLUDE_DIRS}")
endif()

project(${PROJECT_LIB_NAME})

# generate libhypervisor.dylib
include_directories(${PROJECT_LIB_NAME}
    ${JNI_INCLUDE_DIRS}
    ${JAVA_INCLUDE_PATH2}
)
add_library(${PROJECT_LIB_NAME} MODULE
    hypervisor.mm
    hypervisor.h
    khash.h
    vcpu.h
    com_github_unidbg_arm_backend_hypervisor_Hypervisor.h
)
set_target_properties(${PROJECT_LIB_NAME} PROPERTIES SUFFIX ".dylib")
target_link_libraries(${PROJECT_LIB_NAME} "-framework Hypervisor -lobjc")
target_link_libraries(${PROJECT_LIB_NAME} ${JNI_LIBRARIES})
