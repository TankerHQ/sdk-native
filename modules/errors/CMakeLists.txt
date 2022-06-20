cmake_minimum_required(VERSION 3.4)

project(Errors)

add_library(tankererrors STATIC
  include/Tanker/Errors/Errc.hpp
  include/Tanker/Errors/ErrcCategory.hpp
  include/Tanker/Errors/AppdErrc.hpp
  include/Tanker/Errors/AppdErrcCategory.hpp
  include/Tanker/Errors/Exception.hpp
  include/Tanker/Errors/AssertionError.hpp
  include/Tanker/Errors/DeviceUnusable.hpp

  src/AssertionError.cpp
  src/DeviceUnusable.cpp
  src/Errc.cpp
  src/ErrcCategory.cpp
  src/AppdErrc.cpp
  src/AppdErrcCategory.cpp
  src/Exception.cpp
)

target_include_directories(tankererrors
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankererrors PUBLIC tankerformat tankerlog Boost fmt::fmt)

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
