cmake_minimum_required(VERSION 3.4)
project(tankeridentity CXX)

add_library(tankertesthelpers STATIC
  include/Helpers/Config.hpp
  include/Helpers/TimeoutTerminate.hpp
  include/Helpers/Const.hpp
  include/Helpers/Barrier.hpp
  include/Helpers/Errors.hpp
  include/Helpers/Email.hpp
  include/Helpers/MakeCoTask.hpp
  include/Helpers/Stepper.hpp
  include/Helpers/UniquePath.hpp
  include/Helpers/Buffers.hpp
  include/Helpers/WaitForSignal.hpp
  include/Helpers/TransformTo.hpp
  include/Helpers/WaitFor.hpp
  include/Helpers/JsonFile.hpp

  src/Config.cpp
  src/Email.cpp
  src/TimeoutTerminate.cpp
  src/Barrier.cpp
  src/Stepper.cpp
  src/UniquePath.cpp
  src/JsonFile.cpp
)

target_include_directories(tankertesthelpers
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

install(TARGETS tankertesthelpers
  EXPORT tankertesthelpers
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

target_link_libraries(tankertesthelpers tankertrustchain tankererrors tankertypes CONAN_PKG::boost CONAN_PKG::nlohmann_json CONAN_PKG::fmt)
