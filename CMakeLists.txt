cmake_minimum_required(VERSION 3.20)
project(gdbstub_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(GDBSTUB_SANITIZE "Enable address/undefined sanitizers in Debug builds" OFF)
set(_gdbstub_default_tests OFF)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(_gdbstub_default_tests ON)
endif()
option(GDBSTUB_BUILD_TESTS "Build gdbstub_cpp tests" ${_gdbstub_default_tests})

function(gdbstub_apply_sanitizers target)
    if (NOT GDBSTUB_SANITIZE)
        return()
    endif()
    if (MSVC)
        return()
    endif()
    target_compile_options(${target} PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
        $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
    )
    target_link_options(${target} PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
endfunction()

add_library(gdbstub)
target_sources(gdbstub PRIVATE
    src/gdbstub/gdbstub.cpp
    src/gdbstub/rsp_core.cpp
    src/gdbstub/server.cpp
    src/gdbstub/transport_tcp.cpp
)
set_target_properties(gdbstub PROPERTIES OUTPUT_NAME gdbstub)
target_include_directories(gdbstub
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/third_party>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(gdbstub PUBLIC cxx_std_20)
add_library(gdbstub::gdbstub ALIAS gdbstub)
gdbstub_apply_sanitizers(gdbstub)

add_library(gdbstub_c)
target_sources(gdbstub_c PRIVATE
    bindings/capi/src/gdbstub_cpp_c.cpp
    src/gdbstub/gdbstub.cpp
    src/gdbstub/rsp_core.cpp
    src/gdbstub/server.cpp
    src/gdbstub/transport_tcp.cpp
)
set_target_properties(gdbstub_c PROPERTIES OUTPUT_NAME gdbstub_c)
target_include_directories(gdbstub_c
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/bindings/capi/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/third_party>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(gdbstub_c PUBLIC cxx_std_20)
gdbstub_apply_sanitizers(gdbstub_c)

add_executable(gdbstub_tool)
target_sources(gdbstub_tool PRIVATE
    src/gdbstub_tool/main.cpp
)
target_link_libraries(gdbstub_tool PRIVATE gdbstub)
gdbstub_apply_sanitizers(gdbstub_tool)

find_package(Threads REQUIRED)
target_link_libraries(gdbstub_tool PRIVATE Threads::Threads)

if (WIN32)
    target_link_libraries(gdbstub PRIVATE ws2_32)
    target_link_libraries(gdbstub_c PRIVATE ws2_32)
    target_link_libraries(gdbstub_tool PRIVATE ws2_32)
endif()

if(GDBSTUB_BUILD_TESTS)
    include(CTest)
    if(BUILD_TESTING)
        add_executable(gdbstub_test)
        target_sources(gdbstub_test PRIVATE
            test/gdbstub/test_main.cpp
            test/gdbstub/test_gdbstub.cpp
            test/gdbstub/test_server.cpp
            test/gdbstub/test_toy_components.cpp
            test/gdbstub/test_toy_emulator.cpp
        )
        set_target_properties(gdbstub_test PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test
            OUTPUT_NAME gdbstub_test
        )
        target_link_libraries(gdbstub_test PRIVATE gdbstub Threads::Threads)
        if(WIN32)
            target_link_libraries(gdbstub_test PRIVATE ws2_32)
        endif()
        gdbstub_apply_sanitizers(gdbstub_test)
        target_include_directories(gdbstub_test PRIVATE ${PROJECT_SOURCE_DIR}/test)

        add_executable(gdbstub_capi_test)
        target_sources(gdbstub_capi_test PRIVATE
            test/gdbstub/test_main.cpp
            test/gdbstub/test_capi.cpp
        )
        set_target_properties(gdbstub_capi_test PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test
            OUTPUT_NAME gdbstub_capi_test
        )
        target_link_libraries(gdbstub_capi_test PRIVATE gdbstub_c Threads::Threads)
        if(WIN32)
            target_link_libraries(gdbstub_capi_test PRIVATE ws2_32)
        endif()
        gdbstub_apply_sanitizers(gdbstub_capi_test)
        target_include_directories(gdbstub_capi_test PRIVATE
            ${PROJECT_SOURCE_DIR}/test
            ${PROJECT_SOURCE_DIR}/bindings/capi/include
        )

        enable_testing()
        add_test(NAME gdbstub_test COMMAND gdbstub_test)
        add_test(NAME gdbstub_capi_test COMMAND gdbstub_capi_test)

        find_program(LLDB_EXECUTABLE lldb)
        find_package(Python3 COMPONENTS Interpreter)
        if(LLDB_EXECUTABLE AND Python3_Interpreter_FOUND)
            set(LLDB_E2E_SCRIPT ${PROJECT_SOURCE_DIR}/test/gdbstub/lldb_e2e_test.py)
            foreach(mode IN ITEMS blocking polling async)
                add_test(
                    NAME gdbstub_lldb_e2e_${mode}
                    COMMAND ${Python3_EXECUTABLE}
                            ${LLDB_E2E_SCRIPT}
                            --lldb ${LLDB_EXECUTABLE}
                            --gdbstub-tool ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/gdbstub_tool
                            --mode ${mode}
                )
                set_tests_properties(gdbstub_lldb_e2e_${mode} PROPERTIES LABELS "lldb")
            endforeach()
        endif()
    endif()
endif()

find_program(CLANG_FORMAT NAMES clang-format clang-format-17 clang-format-16)
if(CLANG_FORMAT)
    file(GLOB_RECURSE FORMAT_SOURCES
        ${PROJECT_SOURCE_DIR}/src/*.cpp
        ${PROJECT_SOURCE_DIR}/src/*.hpp
        ${PROJECT_SOURCE_DIR}/test/*.cpp
        ${PROJECT_SOURCE_DIR}/test/*.hpp
    )

    list(FILTER FORMAT_SOURCES EXCLUDE REGEX "/lib/third_party/")
    add_custom_target(gdbstub_cpp-format
        COMMAND ${CLANG_FORMAT} -i ${FORMAT_SOURCES}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "formatting source files"
        VERBATIM
    )
endif()
