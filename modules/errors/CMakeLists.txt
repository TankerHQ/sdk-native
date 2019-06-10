cmake_minimum_required(VERSION 3.4)

project(Errors)

add_library(tankererrors STATIC
  include/Tanker/Errors/Errc.hpp
  include/Tanker/Errors/ErrcCategory.hpp
  include/Tanker/Errors/Exception.hpp
  include/Tanker/Errors/AssertionError.hpp

  src/AssertionError.cpp
  src/Errc.cpp
  src/ErrcCategory.cpp
  src/Exception.cpp
)

target_include_directories(tankererrors
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankererrors PUBLIC tankerformat tankerlog CONAN_PKG::Boost CONAN_PKG::fmt)

install(DIRECTORY include DESTINATION .)
install(TARGETS tankererrors
  EXPORT tankererrors
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

if (BUILD_TESTS)
  add_subdirectory(test)
endif()
