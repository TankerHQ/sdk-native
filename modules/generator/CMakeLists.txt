cmake_minimum_required(VERSION 3.4)

project(Generator)

add_library(generator
  include/Generator/Generator.hpp
  include/Generator/Device.hpp
  include/Generator/Resource.hpp
  include/Generator/Utils.hpp
  include/Generator/BlockTypes.hpp

  src/Generator.cpp
  src/Device.cpp
  src/Resource.cpp
  src/Utils.cpp
)

add_executable(tgen
  main.cpp
)

target_include_directories(generator
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(generator tankercore CONAN_PKG::cppcodec)

target_link_libraries(tgen PRIVATE generator)

if(BUILD_TESTS)
  add_subdirectory(test)
endif()
