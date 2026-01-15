cmake_minimum_required(VERSION 3.20)
project(gdbstub_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_library(gdbstub)
target_sources(gdbstub PRIVATE
    src/gdbstub/gdbstub.cpp
)
set_target_properties(gdbstub PROPERTIES OUTPUT_NAME gdbstub)
target_include_directories(gdbstub
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/lib/third_party
)
target_compile_features(gdbstub PUBLIC cxx_std_20)
add_library(gdbstub::gdbstub ALIAS gdbstub)

add_executable(gdbstub_tool)
target_sources(gdbstub_tool PRIVATE
    src/gdbstub_tool/main.cpp
)
target_link_libraries(gdbstub_tool PRIVATE gdbstub)

add_executable(gdbstub_test)
target_sources(gdbstub_test PRIVATE
    test/gdbstub/test_main.cpp
    test/gdbstub/test_gdbstub.cpp
)
set_target_properties(gdbstub_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test
    OUTPUT_NAME gdbstub_test
)
target_link_libraries(gdbstub_test PRIVATE gdbstub)

enable_testing()
add_test(NAME gdbstub_test COMMAND gdbstub_test)

find_program(CLANG_FORMAT NAMES clang-format clang-format-17 clang-format-16)
if(CLANG_FORMAT)
    file(GLOB_RECURSE FORMAT_SOURCES
        ${CMAKE_SOURCE_DIR}/src/*.cpp
        ${CMAKE_SOURCE_DIR}/src/*.hpp
        ${CMAKE_SOURCE_DIR}/test/*.cpp
        ${CMAKE_SOURCE_DIR}/test/*.hpp
    )

    list(FILTER FORMAT_SOURCES EXCLUDE REGEX "/lib/third_party/")
    add_custom_target(gdbstub_cpp-format
        COMMAND ${CLANG_FORMAT} -i ${FORMAT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "formatting source files"
        VERBATIM
    )
endif()
