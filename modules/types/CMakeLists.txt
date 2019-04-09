cmake_minimum_required(VERSION 3.4)

project(types)

add_library(tankertypes INTERFACE)

target_sources(tankertypes INTERFACE
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SUserId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/UserId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SGroupId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SResourceId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/GroupId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/TrustchainId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/DeviceId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/StringWrapper.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/Email.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/Password.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/ResourceId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/UnlockKey.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/VerificationCode.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SDeviceId.hpp
)

target_include_directories(tankertypes
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

target_link_libraries(tankertypes INTERFACE tankercrypto)
