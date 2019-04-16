cmake_minimum_required(VERSION 3.4)

project(tankertrustchain)

add_library(tankertrustchain STATIC
  include/Tanker/Trustchain/Actions/Nature.hpp
  include/Tanker/Trustchain/UserId.hpp

  src/Actions/Nature.cpp
  src/ExternTemplates.cpp
)

target_include_directories(tankertrustchain
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

install(TARGETS tankertrustchain
  EXPORT tankertrustchain
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

target_link_libraries(tankertrustchain tankercrypto)
