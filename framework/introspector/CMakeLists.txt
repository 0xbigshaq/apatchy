cmake_minimum_required(VERSION 3.16)
project(wuxi)

# better IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)

# If not found, try to find the LLVM in the default paths
find_package(LLVM REQUIRED CONFIG
    HINTS /usr/lib/llvm-18 /usr/lib/llvm-17 /usr/lib/llvm-16
)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# ++sources
add_executable(wuxi
    src/main.cpp
    src/CallGraphWalker.cpp
    src/FunctionInfo.cpp
    src/JsonOutput.cpp
)

# analysis library is needed for call graph walker
llvm_map_components_to_libnames(llvm_libs
    core support irreader analysis
)

# link the libraries to the final executable
target_link_libraries(wuxi ${llvm_libs})
