cmake_minimum_required(VERSION 3.4)

project(tankerstreams)

add_library(tankerstreams INTERFACE)
target_include_directories(tankerstreams
  INTERFACE
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerstreams INTERFACE CONAN_PKG::tconcurrent)

install(DIRECTORY include DESTINATION .)

install(TARGETS tankerstreams
  EXPORT tankerstreams
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
