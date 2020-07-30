cmake_minimum_required(VERSION 3.4)

project(Network)

set(TANKER_NETWORK_CONNECTION_SRC
  include/Tanker/Network/Connection.hpp
  src/Connection.cpp
)

add_library(tankernetwork STATIC
  include/Tanker/Network/AConnection.hpp
  include/Tanker/Network/ConnectionFactory.hpp
  include/Tanker/Network/SdkInfo.hpp

  src/ConnectionFactory.cpp
  ${TANKER_NETWORK_CONNECTION_SRC}
)

target_include_directories(tankernetwork
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(TANKER_BUILD_WITH_SSL)
  target_link_libraries(tankernetwork tankercacerts)
endif()

target_link_libraries(tankernetwork
  tankerlog
  tankertrustchain
  ttracer

  CONAN_PKG::tconcurrent
  CONAN_PKG::fmt
  CONAN_PKG::mgs
 
  CONAN_PKG::nlohmann_json
)


target_link_libraries(tankernetwork
  CONAN_PKG::socket.io-client-cpp
)

install(DIRECTORY include DESTINATION .)
install(TARGETS tankernetwork
  EXPORT tankernetwork
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
