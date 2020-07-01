cmake_minimum_required(VERSION 3.4)

project(Admin)

add_library(tankeradmin STATIC
  include/Tanker/Admin/Client.hpp

  src/Client.cpp
)

target_include_directories(tankeradmin
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankeradmin
  tankercrypto
  tankertypes
  tankererrors
  tankercacerts
  ttracer
  
  CONAN_PKG::gsl-lite
  CONAN_PKG::mgs
  CONAN_PKG::tconcurrent
  CONAN_PKG::nlohmann_json
  CONAN_PKG::fetchpp
)

install(DIRECTORY include DESTINATION .)
install(TARGETS tankeradmin
  EXPORT tankeradmin
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
