cmake_minimum_required(VERSION 3.4)
project(compat-helpers CXX)

add_library(tankercompathelpers STATIC
  include/Tanker/Compat/Trustchain.hpp
  include/Tanker/Compat/TrustchainFactory.hpp
  include/Tanker/Compat/Command.hpp

  src/Trustchain.cpp
  src/TrustchainFactory.cpp
)

target_include_directories(tankercompathelpers
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

install(TARGETS tankercompathelpers
  EXPORT tankercompathelpers
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

target_link_libraries(tankercompathelpers
  tankercore
  tankertesthelpers
)
