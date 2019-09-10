cmake_minimum_required(VERSION 3.4)

project(tanker_utils-c)

add_library(tanker_utils-c INTERFACE)

target_include_directories(tanker_utils-c
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(TARGETS tanker_utils-c
  EXPORT tanker_utils-c
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
