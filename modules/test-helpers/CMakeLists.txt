cmake_minimum_required(VERSION 3.4)
project(tankerusertoken CXX)

add_library(tankertesthelpers STATIC
  include/Helpers/Config.hpp
  include/Helpers/TimeoutTerminate.hpp
  include/Helpers/Barrier.hpp
  include/Helpers/Stepper.hpp
  include/Helpers/SignalSpy.hpp
  include/Helpers/UniquePath.hpp
  include/Helpers/Buffers.hpp
  include/Helpers/WaitForSignal.hpp

  src/Config.cpp
  src/TimeoutTerminate.cpp
  src/Barrier.cpp
  src/Stepper.cpp
  src/UniquePath.cpp
)

target_include_directories(tankertesthelpers
  PUBLIC
  ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(tankertesthelpers CONAN_PKG::Boost CONAN_PKG::jsonformoderncpp CONAN_PKG::fmt CONAN_PKG::optional-lite)
