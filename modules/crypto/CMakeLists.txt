cmake_minimum_required(VERSION 3.4)

project(tankercrypto)

add_library(tankercrypto STATIC
    src/Crypto.cpp
    src/JsonFormat.cpp

    include/Tanker/Crypto/Crypto.hpp
    include/Tanker/Crypto/InvalidKeySize.hpp
    include/Tanker/Crypto/Types.hpp
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
    include/Tanker/Crypto/Signature.hpp
    include/Tanker/Crypto/SymmetricKey.hpp
    include/Tanker/Crypto/AeadIv.hpp
    include/Tanker/Crypto/detail/CryptographicTypeImpl.hpp
    include/Tanker/Crypto/detail/CryptographicType.hpp
    include/Tanker/Crypto/detail/IsCryptographicType.hpp
    include/Tanker/Crypto/detail/ArrayHelpers.hpp
    include/Tanker/Crypto/AsymmetricKey.hpp
    include/Tanker/Crypto/KeyUsage.hpp
    include/Tanker/Crypto/KeyType.hpp
    include/Tanker/Crypto/KeyFormat.hpp
    include/Tanker/Crypto/JsonFormat.hpp
)

target_include_directories(tankercrypto
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankercrypto tankerserialization CONAN_PKG::libsodium CONAN_PKG::cppcodec CONAN_PKG::gsl-lite CONAN_PKG::jsonformoderncpp CONAN_PKG::fmt)

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
