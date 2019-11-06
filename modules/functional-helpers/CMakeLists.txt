cmake_minimum_required(VERSION 3.4)

project(tankerfunctionalhelpers)

add_library(tankerfunctionalhelpers STATIC
  include/Tanker/Functional/Trustchain.hpp
  include/Tanker/Functional/TrustchainFactory.hpp
  include/Tanker/Functional/User.hpp
  include/Tanker/Functional/Device.hpp
  include/Tanker/Functional/TrustchainFixture.hpp
  include/Tanker/Functional/Fetcher.hpp

  src/Trustchain.cpp
  src/TrustchainFactory.cpp
  src/TrustchainFixture.cpp
  src/User.cpp
  src/Device.cpp
)

target_include_directories(tankerfunctionalhelpers
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(
  tankerfunctionalhelpers
  PUBLIC
    tankercore
    tankertesthelpers
    tankeradmin
)

install(TARGETS tankerfunctionalhelpers
  EXPORT tankerfunctionalhelpers
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include DESTINATION .)
