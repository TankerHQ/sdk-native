cmake_minimum_required(VERSION 3.4)
project(tanker)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")
set(CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_PREFIX_PATH}")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
message(STATUS "Building with ${CMAKE_BUILD_TYPE} settings")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BUILD_TESTS "Enable test building" ON)
option(TANKER_BUILD_WITH_SSL "Tanker uses ssl" ON)
option(WITH_COVERAGE "Enable coverage" OFF)
option(BUILD_TANKER_TOOLS "Build Tanker Tools" ON)
option(WITH_TRACER "Enable tracer library" OFF)
option(TANKERLIB_SHARED "whether to build the main tanker library as a shared" OFF)
option(WARN_AS_ERROR "Add -Werror during compilation" OFF)

add_definitions("-DGSL_THROW_ON_CONTRACT_VIOLATION")

if(WIN32)
  # just because
  add_definitions("-DWIN32_MEAN_AND_LEAN")

  # because of Boost.Log
  add_definitions("-D_WIN32_WINNT=0x0601")

  # allow using std::min, std::max
  add_definitions("-DNOMINMAX")

  # allow tanker to allocate more than 1gb of ram
  if(MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LARGEADDRESSAWARE")
  endif()
endif()

if(BUILD_TESTS)
  enable_testing()
endif()

# CMAKE_C_FLAGS and the like are _strings_, not lists.
# So, we need a macro so that we can rewrite the values
# in place, and avoid appending the flags twice
macro(tanker_add_flags var flags)
  string(FIND "${${var}}" ${flags} _res)
  if(${_res} EQUAL "-1")
    set(${var} "${${var}} ${flags}")
  endif()
endmacro()

if (MINGW)
  # optimization flags are missing by default, and cause "file too big" errors
  tanker_add_flags(CMAKE_CXX_FLAGS_DEBUG "-Og")
  tanker_add_flags(CMAKE_CXX_FLAGS_RELEASE "-O3")
  tanker_add_flags(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O3 -g")
  tanker_add_flags(CMAKE_CXX_FLAGS_MINSIZEREL "-Os")
endif()

if(${WITH_COVERAGE})
  if(WIN32)
    message(WARNING "WITH_COVERAGE ignored on Windows")
  else()
    message(STATUS "Building with coverage")
    tanker_add_flags(CMAKE_C_FLAGS "--coverage")
    tanker_add_flags(CMAKE_CXX_FLAGS "--coverage")
    tanker_add_flags(CMAKE_EXE_LINKER_FLAGS "--coverage")
    tanker_add_flags(CMAKE_SHARED_LINKER_FLAGS "--coverage")
    tanker_add_flags(CMAKE_MODULE_LINKER_FLAGS "--coverage")
  endif()
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  # warns about void foo(); (should be void foo(void);).
  tanker_add_flags(CMAKE_C_FLAGS "-Wstrict-prototypes")
  set(COMMON_COMPILE_FLAGS "-Wall -Wextra -pedantic -Wno-unused-parameter -Wmissing-declarations -Werror=return-type")
  if(WARN_AS_ERROR)
    tanker_add_flags(CMAKE_CXX_FLAGS "-Werror")
  endif()
elseif(MSVC)
  set(COMMON_COMPILE_FLAGS "/MP /bigobj")
endif()

tanker_add_flags(CMAKE_C_FLAGS ${COMMON_COMPILE_FLAGS})
tanker_add_flags(CMAKE_CXX_FLAGS ${COMMON_COMPILE_FLAGS})

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # clang with libstdc++ 7.2 warns because tuple_size is defined as a struct
  # instead of a class
  tanker_add_flags(CMAKE_CXX_FLAGS "-Wno-mismatched-tags")
endif()

add_subdirectory(modules/admin)
add_subdirectory(modules/admin-c)
add_subdirectory(modules/utils-c)
add_subdirectory(modules/async)
add_subdirectory(modules/config)
add_subdirectory(modules/crypto)
add_subdirectory(modules/errors)
add_subdirectory(modules/format)
add_subdirectory(modules/identity)
add_subdirectory(modules/log)
add_subdirectory(modules/functional-helpers)
add_subdirectory(modules/test-helpers)
add_subdirectory(modules/network)
add_subdirectory(modules/sdk-core)
add_subdirectory(modules/sdk-c)
add_subdirectory(modules/serialization)
add_subdirectory(modules/streams)
add_subdirectory(modules/tracer)
add_subdirectory(modules/trustchain)
add_subdirectory(modules/types)

if (TANKER_BUILD_WITH_SSL)
  add_subdirectory(modules/cacerts)
endif()

if (BUILD_TESTS)
  add_subdirectory(modules/functional-tests)
endif()

if (BUILD_BENCH)
  add_subdirectory(modules/bench)
endif()

if(${BUILD_TANKER_TOOLS})
  add_subdirectory(modules/cli)
endif()

if(WITH_COVERAGE)
  # gcov version must match GCC version
  string(REGEX MATCH "([0-9])\.[0-9]\.[0-9]" _out ${CMAKE_CXX_COMPILER_VERSION})
  set(COVERAGE_FILE ${CMAKE_BINARY_DIR}/coverage.info)
  add_custom_target(coverage
    COMMAND lcov
      --base-directory ${CMAKE_BINARY_DIR}
      --directory ${CMAKE_BINARY_DIR}
      --capture
      --rc lcov_branch_coverage=1
      --gcov-tool /usr/bin/gcov-${CMAKE_MATCH_1}
      --output-file ${COVERAGE_FILE}
    COMMAND lcov
      --remove ${COVERAGE_FILE} */usr/include* boost* */.conan/* */test/* */Test/* *test-helpers/*
      --rc lcov_branch_coverage=1
      --gcov-tool /usr/bin/gcov-${CMAKE_MATCH_1}
      --output-file ${COVERAGE_FILE}
    COMMAND genhtml
      ${CMAKE_BINARY_DIR}/coverage.info
      --branch-coverage
      --output-directory ${CMAKE_BINARY_DIR}/coverage
    USES_TERMINAL
  )
endif()
