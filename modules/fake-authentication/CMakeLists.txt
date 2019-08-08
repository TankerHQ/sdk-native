cmake_minimum_required(VERSION 3.4)

project(fake-authentication)

add_library(tankerfakeauthentication STATIC
  include/Tanker/FakeAuthentication/FakeAuthentication.hpp

  src/FakeAuthentication.cpp
)

target_include_directories(tankerfakeauthentication
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerfakeauthentication PUBLIC
  tankercacerts
  tankererrors
  tankerlog
  tccurl
  CONAN_PKG::fmt
  CONAN_PKG::jsonformoderncpp
  CONAN_PKG::optional-lite
  CONAN_PKG::tconcurrent
)

install(DIRECTORY include DESTINATION .)
install(TARGETS tankerfakeauthentication
  EXPORT tankerfakeauthentication
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

if (BUILD_TESTS)
  add_subdirectory(test)
endif()
