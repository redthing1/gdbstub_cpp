cmake_minimum_required(VERSION 3.15)
project(GdbStubTests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Create the test helper executable
add_executable(test_helper test_helper.cpp)

# Include the gdbstub header directory
target_include_directories(test_helper PRIVATE ../src)

# Enable debug logging for tests
target_compile_definitions(test_helper PRIVATE GDBSTUB_DEBUG)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(test_helper PRIVATE ws2_32)
endif()

# Add compile options for better debugging
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_helper PRIVATE 
        -Wall -Wextra -pedantic
        $<$<CONFIG:Debug>:-g3 -O0>
        $<$<CONFIG:Release>:-O2>
    )
elseif(MSVC)
    target_compile_options(test_helper PRIVATE
        /W4
        $<$<CONFIG:Debug>:/Od /Zi>
        $<$<CONFIG:Release>:/O2>
    )
endif()

# Optional: Add a test that just verifies the helper builds and runs
add_test(NAME test_helper_builds 
         COMMAND test_helper --help
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(test_helper_builds PROPERTIES 
    WILL_FAIL TRUE  # We expect this to fail with usage message
    TIMEOUT 5
)