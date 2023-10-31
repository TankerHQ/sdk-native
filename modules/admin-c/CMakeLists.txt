cmake_minimum_required(VERSION 3.10)

project(tanker_admin-c)
include(GenerateExportHeader)
include(TankerExportSymbols)
include(TankerLinkLibraries)

if(TANKERLIB_SHARED)
  set(tankerlib_type SHARED)
else()
  set(tankerlib_type STATIC)
endif()

add_library(tanker_admin-c ${tankerlib_type}
  include/ctanker/admin.h

  src/admin.cpp
)

generate_export_header(tanker_admin-c
  EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/ctanker/admin/export.h
)

target_include_directories(tanker_admin-c
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if (TANKERLIB_SHARED)
  tanker_export_symbols(tanker_admin-c)
  if (MINGW)
    set_target_properties(tanker_admin-c PROPERTIES PREFIX "")
    set(_additional_link_flags "-Wl,-static;-static-libgcc")
  # We compile for older Linux distro which don't have an up to date libstdc++
  # Ignore that for clang because libc++ isn't compiled with -fPIC, and we don't
  # ship clang build for Linux anyway.
  elseif(UNIX AND NOT APPLE AND NOT ANDROID AND NOT (CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
    set(_additional_link_flags "-static-libstdc++")
  endif()
endif()

target_link_libraries(tanker_admin-c)

tanker_link_libraries(tanker_admin-c
  tankeradmin
  tanker_utils-c
  tankercrypto
  tankererrors

  ${_additional_link_flags}

  EMBED_LIBS
    tanker_async
)

install(TARGETS tanker_admin-c
  EXPORT tanker_admin-c
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include DESTINATION .)
install(DIRECTORY ${CMAKE_BINARY_DIR}/include DESTINATION .)
