cmake_minimum_required(VERSION 3.4)

project(Serialization)

add_library(tankerserialization STATIC
  src/Varint.cpp
)

target_include_directories(tankerserialization
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerserialization PUBLIC CONAN_PKG::gsl-lite CONAN_PKG::optional-lite CONAN_PKG::fmt CONAN_PKG::variant)

install(DIRECTORY include DESTINATION .)

install(TARGETS tankerserialization
  EXPORT tankerserialization
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

if(BUILD_TESTS)
  add_subdirectory(test)
endif()
