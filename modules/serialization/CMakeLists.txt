cmake_minimum_required(VERSION 3.4)

project(Serialization)

add_library(tankerserialization STATIC
  include/Tanker/Serialization/from_serialized.hpp
  include/Tanker/Serialization/serialized_size.hpp
  include/Tanker/Serialization/to_serialized.hpp
  include/Tanker/Serialization/Serialization.hpp
  include/Tanker/Serialization/SerializedSource.hpp
  include/Tanker/Serialization/Varint.hpp
  include/Tanker/Serialization/Errors/Errc.hpp
  include/Tanker/Serialization/Errors/ErrcCategory.hpp
  include/Tanker/Serialization/detail/static_const.hpp

  src/Varint.cpp
  src/Errors/ErrcCategory.cpp
  src/Errors/Errc.cpp
)

target_include_directories(tankerserialization
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(
  tankerserialization
  PUBLIC
  tankererrors

  CONAN_PKG::gsl-lite
  CONAN_PKG::optional-lite
  CONAN_PKG::fmt
  CONAN_PKG::variant
)

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
