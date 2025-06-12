cmake_minimum_required(VERSION 3.15)
project(gdbstub_cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Create the header-only library target
add_library(gdbstub INTERFACE)
add_library(gdbstub::gdbstub ALIAS gdbstub)

# Set include directories
target_include_directories(gdbstub INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(gdbstub INTERFACE ws2_32)
endif()

# Export the target for use by submodules/consumers
include(CMakePackageConfigHelpers)

# Install the header file
install(FILES src/gdbstub.hpp
    DESTINATION include
)

# Install the library target
install(TARGETS gdbstub
    EXPORT gdbstub-targets
    INCLUDES DESTINATION include
)

# Install the export set
install(EXPORT gdbstub-targets
    FILE gdbstub-targets.cmake
    NAMESPACE gdbstub::
    DESTINATION lib/cmake/gdbstub
)

# Create package config file
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gdbstub-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/gdbstub-config.cmake"
    INSTALL_DESTINATION lib/cmake/gdbstub
)

# Create package version file
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/gdbstub-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install package config files
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/gdbstub-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/gdbstub-config-version.cmake"
    DESTINATION lib/cmake/gdbstub
)

# Enable testing
option(GDBSTUB_BUILD_TESTS "Build gdbstub tests" ON)
if(GDBSTUB_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()