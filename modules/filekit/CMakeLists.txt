cmake_minimum_required(VERSION 3.4)

project(tanker-filekit)

add_library(tankerfilekit STATIC
  include/Tanker/FileKit/DownloadStream.hpp
  include/Tanker/FileKit/FileKit.hpp

  src/DownloadStream.cpp
  src/FileKit.cpp
)

target_include_directories(tankerfilekit
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerfilekit PUBLIC
  tankercrypto
  tankercacerts
  tankercore
  tankererrors
  tankerlog
  tankertrustchain
  tccurl
  CONAN_PKG::fmt
  CONAN_PKG::gsl-lite
  CONAN_PKG::jsonformoderncpp
  CONAN_PKG::optional-lite
  CONAN_PKG::tconcurrent
)

install(DIRECTORY include DESTINATION .)
install(TARGETS tankerfilekit
  EXPORT tankerfilekit
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

if (BUILD_TESTS)
  add_subdirectory(test)
endif()
