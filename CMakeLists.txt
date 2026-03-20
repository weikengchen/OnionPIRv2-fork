cmake_minimum_required(VERSION 3.13)

# Set build type to Benchmark if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Benchmark)
endif()

# ==================== Compiler Selection ====================
# On macOS ARM64, use GCC from Homebrew for OpenMP support.
# On Linux, use system GCC.
if (APPLE)
    # Look for Homebrew GCC (g++-15, g++-14, etc.)
    find_program(GCC_CXX NAMES g++-15 g++-14 g++-13 PATHS /opt/homebrew/bin NO_DEFAULT_PATH)
    find_program(GCC_CC  NAMES gcc-15 gcc-14 gcc-13 PATHS /opt/homebrew/bin NO_DEFAULT_PATH)
    if (GCC_CXX AND GCC_CC)
        set(CMAKE_C_COMPILER  ${GCC_CC})
        set(CMAKE_CXX_COMPILER ${GCC_CXX})
        message(STATUS "Using Homebrew GCC: ${GCC_CXX}")
    else()
        message(WARNING "Homebrew GCC not found, falling back to default compiler. OpenMP may not work.")
    endif()
else()
    set(CMAKE_C_COMPILER  /usr/bin/gcc)
    set(CMAKE_CXX_COMPILER /usr/bin/g++)
endif()

# Ask every target in this project to compile as C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)   # fail if the compiler can't do C++20
set(CMAKE_CXX_EXTENSIONS  OFF)        # use -std=c++20, not gnu++20

# Automatically enables all available optimizations for your local machine
if (APPLE)
    # On ARM macOS with GCC, -march=native can fail. Use -mcpu=native instead.
    set(CMAKE_CXX_FLAGS "-O3 -MD -mcpu=native")
    set(CMAKE_OSX_ARCHITECTURES "")  # Prevent CMake from adding -arch flag
else()
    set(CMAKE_CXX_FLAGS "-O3 -MD -march=native -mtune=native")
endif()

# Add perf when building in Debug mode
if (CMAKE_BUILD_TYPE MATCHES Debug)
    if (APPLE)
        set(CMAKE_CXX_FLAGS "-O2 -MD -pg -mcpu=native")
    else()
        set(CMAKE_CXX_FLAGS "-O2 -MD -pg -march=native -mtune=native")
    endif()
endif()


# Option to enable Intel HEXL optimizations. Default OFF on Apple Silicon.
if (APPLE)
    option(USE_HEXL "Enable Intel HEXL optimizations" OFF)
else()
    option(USE_HEXL "Enable Intel HEXL optimizations" ON)
endif()

if (USE_HEXL)
    message(STATUS "HEXL support enabled.")
    add_compile_definitions(ONIONPIR_USE_HEXL)

    # Set HEXL installation path
    set(HEXL_DIR "/u/yuec12/OnionPIRv2/hexl_install/lib64/cmake/hexl-1.2.6")

    # Find HEXL package
    find_package(HEXL REQUIRED)
    if(HEXL_FOUND)
        message(STATUS "HEXL found at: ${HEXL_DIR}")
    else()
        message(FATAL_ERROR "HEXL not found. Please install HEXL or disable USE_HEXL option.")
    endif()
else()
    message(STATUS "HEXL support disabled.")
endif()


option(NOAVX512 "Disable AVX-512" OFF)
option(NOAVX2 "Disable AVX2" OFF)
if (NOAVX512)
    message("Disabling AVX-512")
    add_compile_options(-mno-avx512f)
endif()
if (NOAVX2)
    message("Disabling AVX2")
    add_compile_options(-mno-avx2)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")
set(IS_BENCHMARK_BUILD CMAKE_BUILD_TYPE STREQUAL "Benchmark")
if (${IS_BENCHMARK_BUILD})
    add_compile_definitions(_BENCHMARK)
endif ()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(Onion-PIR)

# ==================== OpenMP ====================
find_package(OpenMP REQUIRED)

# Automatically find all source files in src/
file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_executable(Onion-PIR ${SRC_FILES})

# ==================== SEAL (submodule) ====================
# Build SEAL from extern/SEAL submodule instead of requiring a system install.
# Disable optional dependencies we don't need.
set(SEAL_USE_INTEL_HEXL OFF CACHE BOOL "" FORCE)
set(SEAL_USE_MSGSL      OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZLIB       OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZSTD       OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_DEPS     ON  CACHE BOOL "" FORCE)
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT OFF CACHE BOOL "" FORCE)
add_subdirectory(extern/SEAL)
target_link_libraries(Onion-PIR PUBLIC SEAL::seal)

# Link OpenMP
target_link_libraries(Onion-PIR PUBLIC OpenMP::OpenMP_CXX)

# Link HEXL if enabled
if (USE_HEXL AND HEXL_FOUND)
    target_link_libraries(Onion-PIR PUBLIC HEXL::hexl)
endif()

# Include directories
target_include_directories(Onion-PIR PUBLIC src/includes)
