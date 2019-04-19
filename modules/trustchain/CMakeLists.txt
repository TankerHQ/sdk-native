cmake_minimum_required(VERSION 3.4)

project(tankertrustchain)

add_library(tankertrustchain STATIC
  include/Tanker/Trustchain/Actions/Nature.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v1.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v2.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v3.hpp
  include/Tanker/Trustchain/Actions/TrustchainCreation.hpp
  include/Tanker/Trustchain/Serialization/DeviceCreation.hpp
  include/Tanker/Trustchain/Serialization/DeviceCreation/v1.hpp
  include/Tanker/Trustchain/Serialization/DeviceCreation/v2.hpp
  include/Tanker/Trustchain/Serialization/DeviceCreation/v3.hpp
  include/Tanker/Trustchain/Serialization/TrustchainCreation.hpp
  include/Tanker/Trustchain/Json/DeviceCreation.hpp
  include/Tanker/Trustchain/Json/DeviceCreation/v1.hpp
  include/Tanker/Trustchain/Json/DeviceCreation/v2.hpp
  include/Tanker/Trustchain/Json/DeviceCreation/v3.hpp
  include/Tanker/Trustchain/Json/TrustchainCreation.hpp
  include/Tanker/Trustchain/UserId.hpp
  include/Tanker/Trustchain/TrustchainId.hpp

  src/Actions/Nature.cpp
  src/Actions/DeviceCreation.cpp
  src/Actions/DeviceCreation/v1.cpp
  src/Actions/DeviceCreation/v2.cpp
  src/Actions/DeviceCreation/v3.cpp
  src/Actions/KeyPublishToDevice.cpp
  src/Actions/TrustchainCreation.cpp
  src/Json/DeviceCreation.cpp
  src/Json/DeviceCreation/v1.cpp
  src/Json/DeviceCreation/v2.cpp
  src/Json/DeviceCreation/v3.cpp
  src/Json/KeyPublishToDevice.cpp
  src/Json/TrustchainCreation.cpp
  src/Serialization/DeviceCreation.cpp
  src/Serialization/DeviceCreation/v1.cpp
  src/Serialization/DeviceCreation/v2.cpp
  src/Serialization/DeviceCreation/v3.cpp
  src/Serialization/KeyPublishToDevice.cpp
  src/Serialization/TrustchainCreation.cpp
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

target_link_libraries(tankertrustchain tankercrypto tankerserialization CONAN_PKG::variant CONAN_PKG::jsonformoderncpp)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
