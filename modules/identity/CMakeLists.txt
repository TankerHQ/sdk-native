cmake_minimum_required(VERSION 3.4)

project(tankeridentity)

add_library(tankeridentity STATIC
  include/Tanker/Identity/UserToken.hpp
  include/Tanker/Identity/Delegation.hpp
  include/Tanker/Identity/Utils.hpp

  src/UserToken.cpp
  src/Delegation.cpp
  src/Utils.cpp
)

target_include_directories(tankeridentity
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

target_link_libraries(tankeridentity tankertypes tankercrypto CONAN_PKG::jsonformoderncpp CONAN_PKG::gsl-lite)

install(TARGETS tankeridentity
  EXPORT tankeridentity
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
