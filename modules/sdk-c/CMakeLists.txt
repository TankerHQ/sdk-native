cmake_minimum_required(VERSION 3.4)

project(TankerSDK-C)

add_library(tanker
  include/tanker.h
  include/tanker/tanker.h
  include/tanker/async.h
  include/tanker/base64.h
  include/tanker/chunk_encryptor.h
  include/tanker/user_token.h
  include/tanker/admin.h
  include/tanker/groups.h

  src/async.cpp
  src/base64.cpp
  src/tanker.cpp
  src/chunk_encryptor.cpp
  src/CFuture.hpp
  src/Utils.hpp
  src/user_token.cpp
  src/admin.cpp
  src/groups.cpp
)

target_link_libraries(tanker PUBLIC tankercore tankercrypto tankerusertoken)
target_include_directories(tanker
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
if(BUILD_SHARED_LIBS)
  if (UNIX AND NOT APPLE) # this means linux, including android
    set_target_properties(tanker PROPERTIES
      LINK_FLAGS -Wl,--version-script=${PROJECT_SOURCE_DIR}/exports.ld)
  else()
    # you need to write an export file for your platform to support that
    message(FATAL_ERROR "Shared library building is not supported on this platform")
  endif()
endif()

target_compile_definitions(tanker PRIVATE FMT_STRING_ALIAS)

install(TARGETS tanker
  EXPORT tanker
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  # PUBLIC_HEADER DESTINATION include
)

install(DIRECTORY include DESTINATION .)

if(BUILD_TESTS)
  add_subdirectory(test)
endif()
