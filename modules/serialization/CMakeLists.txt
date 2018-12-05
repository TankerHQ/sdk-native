cmake_minimum_required(VERSION 3.4)

project(Serialization)

add_library(tankerserialization INTERFACE)

target_include_directories(tankerserialization
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerserialization INTERFACE CONAN_PKG::gsl-lite CONAN_PKG::optional-lite CONAN_PKG::fmt CONAN_PKG::variant)

if(BUILD_TESTS)
  add_subdirectory(test)
endif()
