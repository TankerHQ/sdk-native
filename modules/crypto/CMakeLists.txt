cmake_minimum_required(VERSION 3.10)

project(tankercrypto)

add_library(tankercrypto STATIC
    src/Crypto.cpp
    src/Init.cpp
    src/ExternTemplates.cpp
    src/Errors/Errc.cpp
    src/Errors/ErrcCategory.cpp
    src/EncryptedSymmetricKey.cpp
    src/Format.cpp
    src/Padding.cpp

    include/Tanker/Crypto/IsCryptographicType.hpp
    include/Tanker/Crypto/PublicSignatureKey.hpp
    include/Tanker/Crypto/PrivateSignatureKey.hpp
    include/Tanker/Crypto/PrivateEncryptionKey.hpp
    include/Tanker/Crypto/PublicEncryptionKey.hpp
    include/Tanker/Crypto/EncryptionKeyPair.hpp
    include/Tanker/Crypto/SignatureKeyPair.hpp
    include/Tanker/Crypto/KeyPair.hpp
    include/Tanker/Crypto/BasicHash.hpp
    include/Tanker/Crypto/Hash.hpp
    include/Tanker/Crypto/Mac.hpp
    include/Tanker/Crypto/Init.hpp
    include/Tanker/Crypto/Sealed.hpp
    include/Tanker/Crypto/SealedKeyPair.hpp
    include/Tanker/Crypto/SealedSignatureKeyPair.hpp
    include/Tanker/Crypto/SealedEncryptionKeyPair.hpp
    include/Tanker/Crypto/Signature.hpp
    include/Tanker/Crypto/SealedPrivateEncryptionKey.hpp
    include/Tanker/Crypto/SealedPrivateSignatureKey.hpp
    include/Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp
    include/Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp
    include/Tanker/Crypto/EncryptedSymmetricKey.hpp
    include/Tanker/Crypto/SealedSymmetricKey.hpp
    include/Tanker/Crypto/SymmetricKey.hpp
    include/Tanker/Crypto/SubkeySeed.hpp
    include/Tanker/Crypto/AeadIv.hpp
    include/Tanker/Crypto/SimpleResourceId.hpp
    include/Tanker/Crypto/CompositeResourceId.hpp
    include/Tanker/Crypto/BasicCryptographicType.hpp
    include/Tanker/Crypto/detail/BasicCryptographicTypeImpl.hpp
    include/Tanker/Crypto/AsymmetricKey.hpp
    include/Tanker/Crypto/KeyUsage.hpp
    include/Tanker/Crypto/KeyType.hpp
    include/Tanker/Crypto/Errors/Errc.hpp
    include/Tanker/Crypto/Errors/ErrcCategory.hpp
    include/Tanker/Crypto/Format/Format.hpp
    include/Tanker/Crypto/Json/Json.hpp
    include/Tanker/Crypto/Serialization/Serialization.hpp
    include/Tanker/Crypto/Padding.hpp
)

target_include_directories(tankercrypto
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(
  tankercrypto
  tankerserialization
  tankererrors
  tankertypes

  libsodium::libsodium
  mgs::mgs
  gsl-lite::gsl-lite
  nlohmann_json::nlohmann_json
  fmt::fmt
  range-v3::range-v3
)

install(TARGETS tankercrypto
  EXPORT tankercrypto
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include DESTINATION .)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
