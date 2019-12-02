cmake_minimum_required(VERSION 3.5)
project(compat-v2.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

add_executable(compat
  main.cpp
  src/Command.cpp
  src/States.cpp
  src/Helpers.cpp

  tests/Encrypt.cpp
  tests/Group.cpp
  tests/Unlock.cpp
  tests/PreshareAndClaim.cpp
  tests/DecryptOldClaim.cpp
  tests/ProvisionalUserGroupClaim.cpp
  tests/ProvisionalUserGroupOldClaim.cpp
  tests/ClaimProvisionalSelf.cpp
)

target_include_directories(compat
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(compat CONAN_PKG::docopt.cpp CONAN_PKG::tanker CONAN_PKG::cppcodec)
