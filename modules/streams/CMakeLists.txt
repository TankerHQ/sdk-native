cmake_minimum_required(VERSION 3.4)

project(tankerstreams)

add_library(tankerstreams
  include/Tanker/Streams/InputSource.hpp
  include/Tanker/Streams/Helpers.hpp

  src/Helpers.cpp
)
target_include_directories(tankerstreams
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerstreams PUBLIC CONAN_PKG::tconcurrent CONAN_PKG::gsl-lite)

install(DIRECTORY include DESTINATION .)

install(TARGETS tankerstreams
  EXPORT tankerstreams
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
