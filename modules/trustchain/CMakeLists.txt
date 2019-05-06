cmake_minimum_required(VERSION 3.4)

project(tankertrustchain)

add_library(tankertrustchain STATIC
  include/Tanker/Trustchain/Action.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v1.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v2.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v3.hpp
  include/Tanker/Trustchain/Actions/DeviceRevocation.hpp
  include/Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp
  include/Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp
  include/Tanker/Trustchain/Actions/Nature.hpp
  include/Tanker/Trustchain/Actions/KeyPublishToDevice.hpp
  include/Tanker/Trustchain/Actions/KeyPublishToProvisionalUser.hpp
  include/Tanker/Trustchain/Actions/KeyPublishToUser.hpp
  include/Tanker/Trustchain/Actions/KeyPublishToUserGroup.hpp
  include/Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp
  include/Tanker/Trustchain/Actions/TrustchainCreation.hpp
  include/Tanker/Trustchain/Actions/UserGroupAddition.hpp
  include/Tanker/Trustchain/Actions/UserGroupCreation.hpp
  include/Tanker/Trustchain/Actions/UserGroupCreation/v1.hpp
  include/Tanker/Trustchain/ClientEntry.hpp
  include/Tanker/Trustchain/ServerEntry.hpp
  include/Tanker/Trustchain/DeviceId.hpp
  include/Tanker/Trustchain/GroupId.hpp
  include/Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp
  include/Tanker/Trustchain/ResourceId.hpp
  include/Tanker/Trustchain/Serialization/Action.hpp
  include/Tanker/Trustchain/Serialization/ClientEntry.hpp
  include/Tanker/Trustchain/Serialization/ProvisionalIdentityClaim.hpp
  include/Tanker/Trustchain/Serialization/ServerEntry.hpp
  include/Tanker/Trustchain/Serialization/TrustchainCreation.hpp
  include/Tanker/Trustchain/Serialization/UserGroupAddition.hpp
  include/Tanker/Trustchain/Json/Action.hpp
  include/Tanker/Trustchain/Json/ClientEntry.hpp
  include/Tanker/Trustchain/Json/ProvisionalIdentityClaim.hpp
  include/Tanker/Trustchain/Json/ServerEntry.hpp
  include/Tanker/Trustchain/Json/TrustchainCreation.hpp
  include/Tanker/Trustchain/Json/UserGroupAddition.hpp
  include/Tanker/Trustchain/UserId.hpp
  include/Tanker/Trustchain/TrustchainId.hpp
  include/Tanker/Trustchain/detail/ComputeHash.hpp

  src/Action.cpp
  src/Actions/DeviceCreation.cpp
  src/Actions/DeviceCreation/v1.cpp
  src/Actions/DeviceCreation/v2.cpp
  src/Actions/DeviceCreation/v3.cpp
  src/Actions/DeviceRevocation.cpp
  src/Actions/DeviceRevocation/v1.cpp
  src/Actions/DeviceRevocation/v2.cpp
  src/Actions/Nature.cpp
  src/Actions/KeyPublishToDevice.cpp
  src/Actions/KeyPublishToProvisionalUser.cpp
  src/Actions/KeyPublishToUser.cpp
  src/Actions/KeyPublishToUserGroup.cpp
  src/Actions/ProvisionalIdentityClaim.cpp
  src/Actions/TrustchainCreation.cpp
  src/Actions/UserGroupAddition.cpp
  src/Actions/UserGroupCreation.cpp
  src/Actions/UserGroupCreation/v1.cpp
  src/ClientEntry.cpp
  src/ServerEntry.cpp
  src/Json/Action.cpp
  src/Json/ClientEntry.cpp
  src/Json/ServerEntry.cpp
  src/Json/ProvisionalIdentityClaim.cpp
  src/Json/TrustchainCreation.cpp
  src/Json/UserGroupAddition.cpp
  src/Serialization/Action.cpp
  src/Serialization/ClientEntry.cpp
  src/Serialization/ServerEntry.cpp
  src/Serialization/ProvisionalIdentityClaim.cpp
  src/Serialization/TrustchainCreation.cpp
  src/Serialization/UserGroupAddition.cpp
  src/ExternTemplates.cpp
  src/detail/ComputeHash.cpp
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

target_link_libraries(tankertrustchain tankercrypto tankerserialization tankerformat CONAN_PKG::variant CONAN_PKG::jsonformoderncpp CONAN_PKG::Boost)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
