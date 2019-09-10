cmake_minimum_required(VERSION 3.4)

project(Admin)

add_library(tankeradmin STATIC
  include/Tanker/Admin/Admin.hpp

  src/Admin.cpp
)

target_include_directories(tankeradmin
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankeradmin
  tankernetwork
  tankercrypto
  tankertypes
  tankererrors
  ttracer
  
  CONAN_PKG::gsl-lite
  CONAN_PKG::cppcodec
  CONAN_PKG::tconcurrent
  CONAN_PKG::jsonformoderncpp
)

install(DIRECTORY include DESTINATION .)
install(TARGETS tankeradmin
  EXPORT tankeradmin
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
