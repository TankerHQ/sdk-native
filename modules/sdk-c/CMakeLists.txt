cmake_minimum_required(VERSION 3.4)

project(TankerSDK-C)
include(GenerateExportHeader)
include(TankerExportSymbols)
include(TankerLinkLibraries)

if(TANKERLIB_SHARED)
  set(tankerlib_type SHARED)
else()
  set(tankerlib_type STATIC)
endif()

message(STATUS "Bulding tanker as ${tankerlib_type}")

add_library(ctankerdatastore STATIC
  include/ctanker/datastore.h
  src/datastore.cpp
)

target_include_directories(ctankerdatastore
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(ctankerdatastore PRIVATE
  tankercore
  tanker_utils-c
)

install(TARGETS ctankerdatastore
  EXPORT ctankerdatastore
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

add_library(ctanker ${tankerlib_type}
  include/ctanker.h
  include/ctanker/ctanker.h
  include/ctanker/stream.h
  include/ctanker/identity.h
  include/ctanker/groups.h
  include/ctanker/encryptionsession.h
  include/ctanker/network.h

  src/stream.cpp
  src/ctanker.cpp
  src/identity.cpp
  src/groups.cpp
  src/encryptionsession.cpp
  src/network.cpp

  src/CPadding.hpp
  src/CPadding.cpp
)

generate_export_header(ctanker
  EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/ctanker/export.h
)

if(TANKERLIB_SHARED)
  tanker_export_symbols(ctanker)
  if(MINGW)
    # mingw will create libctanker.dll, which is not found via -lctanker
    set_target_properties(ctanker PROPERTIES PREFIX "")
    set(_additional_link_flags "-Wl,-static;-static-libgcc")
  # We compile for older Linux distro which don't have an up to date libstdc++
  # Ignore that for clang because libc++ isn't compiled with -fPIC, and we don't
  # ship clang build for Linux anyway.
  elseif(UNIX AND NOT APPLE AND NOT ANDROID AND NOT (CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
    set(_additional_link_flags "-static-libstdc++")
  endif()
endif()

tanker_link_libraries(ctanker PUBLIC
  tanker_utils-c
  tankercore
  tankerstreams
  tankercrypto
  tankeridentity

  CONAN_PKG::mgs

  ${_additional_link_flags}

  EMBED_LIBS
    tanker_async
)

target_link_libraries(ctanker PRIVATE
  ctankerdatastore
)

target_include_directories(ctanker
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)


install(TARGETS ctanker
  EXPORT ctanker
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  # PUBLIC_HEADER DESTINATION include
)

install(DIRECTORY include DESTINATION .)
install(DIRECTORY ${CMAKE_BINARY_DIR}/include DESTINATION .)

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

add_subdirectory(datastore-tests)
