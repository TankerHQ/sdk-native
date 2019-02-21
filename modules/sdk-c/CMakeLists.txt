cmake_minimum_required(VERSION 3.4)

project(TankerSDK-C)

if(TANKERLIB_SHARED)
  set(tankerlib_type SHARED)
else()
  set(tankerlib_type STATIC)
endif()

message(STATUS "Bulding tanker as ${tankerlib_type}")

add_library(ctanker ${tankerlib_type}
  include/ctanker.h
  include/ctanker/ctanker.h
  include/ctanker/async.h
  include/ctanker/base64.h
  include/ctanker/chunk_encryptor.h
  include/ctanker/user_token.h
  include/ctanker/admin.h
  include/ctanker/groups.h

  src/async.cpp
  src/base64.cpp
  src/ctanker.cpp
  src/chunk_encryptor.cpp
  src/CFuture.hpp
  src/Utils.hpp
  src/user_token.cpp
  src/admin.cpp
  src/groups.cpp
)

target_link_libraries(ctanker PUBLIC tankercore tankercrypto tankeridentity)
target_include_directories(ctanker
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
if(BUILD_SHARED_LIBS)
  if (UNIX AND NOT APPLE) # this means linux, including android
    set_target_properties(ctanker PROPERTIES
      LINK_FLAGS -Wl,--version-script=${PROJECT_SOURCE_DIR}/exports.ld)
  else()
    # you need to write an export file for your platform to support that
    message(FATAL_ERROR "Shared library building is not supported on this platform")
  endif()
endif()

install(TARGETS ctanker
  EXPORT ctanker
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  # PUBLIC_HEADER DESTINATION include
)

install(DIRECTORY include DESTINATION .)
