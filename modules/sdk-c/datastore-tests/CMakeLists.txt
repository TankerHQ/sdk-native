cmake_minimum_required(VERSION 3.4)

if(TANKERLIB_SHARED)
  set(tankerlib_type SHARED)
else()
  set(tankerlib_type STATIC)
endif()

add_library(tankerdatastoretests ${tankerlib_type}
  test.cpp
)

if (TANKERLIB_SHARED)
  if (MINGW)
    set_target_properties(tankerdatastoretests PROPERTIES PREFIX "")
    set(_additional_link_flags "-Wl,-static;-static-libgcc")
  # We compile for older Linux distro which don't have an up to date libstdc++
  # Ignore that for clang because libc++ isn't compiled with -fPIC, and we don't
  # ship clang build for Linux anyway.
  elseif(UNIX AND NOT APPLE AND NOT ANDROID AND NOT (CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
    set(_additional_link_flags "-static-libstdc++")
  endif()
endif()

tanker_link_libraries(tankerdatastoretests
  tankercore
  tankertesthelpers
  tanker_utils-c
  ctankerdatastore

  CONAN_PKG::doctest

  ${_additional_link_flags}
)

install(TARGETS tankerdatastoretests
  EXPORT tankerdatastoretests
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(FILES test.h DESTINATION include/ctanker/private/datastore-tests)
