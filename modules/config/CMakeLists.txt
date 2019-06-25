cmake_minimum_required(VERSION 3.4)

project(Config)

add_library(tankerconfig INTERFACE)

target_include_directories(tankerconfig
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)
install(TARGETS tankerconfig
  EXPORT tankerconfig
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
