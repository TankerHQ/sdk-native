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

add_library(ctanker ${tankerlib_type}
  include/ctanker.h
  include/ctanker/ctanker.h
  include/ctanker/stream.h
  include/ctanker/identity.h
  include/ctanker/groups.h
  include/ctanker/filekit.h

  src/stream.cpp
  src/ctanker.cpp
  src/identity.cpp
  src/groups.cpp
  src/filekit.cpp
)

generate_export_header(ctanker
  EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/ctanker/export.h
)

if(TANKERLIB_SHARED)
  tanker_export_symbols(ctanker)
endif()

tanker_link_libraries(ctanker PUBLIC
  tanker_utils-c
  tankercore
  tankerstreams
  tankercrypto
  tankeridentity

  CONAN_PKG::cppcodec

  EMBED_LIBS
    tanker_async
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
