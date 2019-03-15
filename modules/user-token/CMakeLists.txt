cmake_minimum_required(VERSION 3.4)

project(tankerusertoken)

add_library(tankerusertoken STATIC
  include/Tanker/UserToken/UserToken.hpp
  include/Tanker/UserToken/Delegation.hpp

  src/UserToken.cpp
  src/Delegation.cpp
)

target_include_directories(tankerusertoken
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

target_link_libraries(tankerusertoken tankertypes tankercrypto CONAN_PKG::jsonformoderncpp CONAN_PKG::gsl-lite)

install(TARGETS tankerusertoken
  EXPORT tankerusertoken
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
