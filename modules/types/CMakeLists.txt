cmake_minimum_required(VERSION 3.10)

project(types)

add_library(tankertypes INTERFACE)

target_sources(tankertypes INTERFACE
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/E2ePassphrase.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/Email.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/EncryptedVerificationKeyForE2ePassphrase.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/EncryptedVerificationKeyForUserKey.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/EncryptedVerificationKeyForUserSecret.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/OidcAuthorizationCode.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/OidcChallenge.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/OidcNonce.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/Overloaded.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/Passphrase.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/PrehashedAndEncryptedPassphrase.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/PreverifiedOidc.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/ProvisionalUserKeys.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SDeviceId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SGroupId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SResourceId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SSecretProvisionalIdentity.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/SUserId.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/StringWrapper.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/TankerSecretProvisionalIdentity.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/VerificationCode.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Types/VerificationKey.hpp
)

target_include_directories(tankertypes
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

target_link_libraries(tankertypes INTERFACE tankertrustchain tankercrypto)
