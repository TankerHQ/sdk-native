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
  include/Tanker/Trustchain/ClientEntry.hpp
  include/Tanker/Trustchain/DeviceId.hpp
  include/Tanker/Trustchain/GroupId.hpp
  include/Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp
  include/Tanker/Trustchain/ResourceId.hpp
  include/Tanker/Trustchain/Serialization/Action.hpp
  include/Tanker/Trustchain/Serialization/ClientEntry.hpp
  include/Tanker/Trustchain/Serialization/DeviceCreation.hpp
  include/Tanker/Trustchain/Serialization/DeviceCreation/v1.hpp
  include/Tanker/Trustchain/Serialization/DeviceCreation/v2.hpp
  include/Tanker/Trustchain/Serialization/DeviceCreation/v3.hpp
  include/Tanker/Trustchain/Serialization/DeviceRevocation.hpp
  include/Tanker/Trustchain/Serialization/DeviceRevocation/v1.hpp
  include/Tanker/Trustchain/Serialization/DeviceRevocation/v2.hpp
  include/Tanker/Trustchain/Serialization/KeyPublishToDevice.hpp
  include/Tanker/Trustchain/Serialization/KeyPublishToProvisionalUser.hpp
  include/Tanker/Trustchain/Serialization/KeyPublishToUser.hpp
  include/Tanker/Trustchain/Serialization/KeyPublishToUserGroup.hpp
  include/Tanker/Trustchain/Serialization/ProvisionalIdentityClaim.hpp
  include/Tanker/Trustchain/Serialization/TrustchainCreation.hpp
  include/Tanker/Trustchain/Serialization/UserGroupAddition.hpp
  include/Tanker/Trustchain/Serialization/UserGroupCreation.hpp
  include/Tanker/Trustchain/Json/Action.hpp
  include/Tanker/Trustchain/Json/ClientEntry.hpp
  include/Tanker/Trustchain/Json/DeviceCreation.hpp
  include/Tanker/Trustchain/Json/DeviceCreation/v1.hpp
  include/Tanker/Trustchain/Json/DeviceCreation/v2.hpp
  include/Tanker/Trustchain/Json/DeviceCreation/v3.hpp
  include/Tanker/Trustchain/Json/DeviceRevocation.hpp
  include/Tanker/Trustchain/Json/DeviceRevocation/v1.hpp
  include/Tanker/Trustchain/Json/DeviceRevocation/v2.hpp
  include/Tanker/Trustchain/Json/KeyPublishToDevice.hpp
  include/Tanker/Trustchain/Json/KeyPublishToProvisionalUser.hpp
  include/Tanker/Trustchain/Json/KeyPublishToUser.hpp
  include/Tanker/Trustchain/Json/KeyPublishToUserGroup.hpp
  include/Tanker/Trustchain/Json/ProvisionalIdentityClaim.hpp
  include/Tanker/Trustchain/Json/TrustchainCreation.hpp
  include/Tanker/Trustchain/Json/UserGroupAddition.hpp
  include/Tanker/Trustchain/Json/UserGroupCreation.hpp
  include/Tanker/Trustchain/UserId.hpp
  include/Tanker/Trustchain/TrustchainId.hpp

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
  src/ClientEntry.cpp
  src/Json/Action.cpp
  src/Json/ClientEntry.cpp
  src/Json/DeviceCreation.cpp
  src/Json/DeviceCreation/v1.cpp
  src/Json/DeviceCreation/v2.cpp
  src/Json/DeviceCreation/v3.cpp
  src/Json/DeviceRevocation.cpp
  src/Json/DeviceRevocation/v1.cpp
  src/Json/DeviceRevocation/v2.cpp
  src/Json/KeyPublishToDevice.cpp
  src/Json/KeyPublishToProvisionalUser.cpp
  src/Json/KeyPublishToUser.cpp
  src/Json/KeyPublishToUserGroup.cpp
  src/Json/ProvisionalIdentityClaim.cpp
  src/Json/TrustchainCreation.cpp
  src/Json/UserGroupAddition.cpp
  src/Json/UserGroupCreation.cpp
  src/Serialization/Action.cpp
  src/Serialization/ClientEntry.cpp
  src/Serialization/DeviceCreation.cpp
  src/Serialization/DeviceCreation/v1.cpp
  src/Serialization/DeviceCreation/v2.cpp
  src/Serialization/DeviceCreation/v3.cpp
  src/Serialization/DeviceRevocation.cpp
  src/Serialization/DeviceRevocation/v1.cpp
  src/Serialization/DeviceRevocation/v2.cpp
  src/Serialization/KeyPublishToDevice.cpp
  src/Serialization/KeyPublishToProvisionalUser.cpp
  src/Serialization/KeyPublishToUser.cpp
  src/Serialization/KeyPublishToUserGroup.cpp
  src/Serialization/ProvisionalIdentityClaim.cpp
  src/Serialization/TrustchainCreation.cpp
  src/Serialization/UserGroupAddition.cpp
  src/Serialization/UserGroupCreation.cpp
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

target_link_libraries(tankertrustchain tankercrypto tankerserialization tankerformat CONAN_PKG::variant CONAN_PKG::jsonformoderncpp CONAN_PKG::Boost)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
