#pragma once

#include <Tanker/Crypto/AsymmetricKey.hpp>
#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>

#include <Tanker/Crypto/detail/ArrayHelpers.hpp>
#include <Tanker/Crypto/detail/CryptographicTypeImpl.hpp>

#include <sodium/crypto_box.h>

#include <array>
#include <cstdint>

namespace Tanker
{
namespace Crypto
{
template <>
class AsymmetricKey<KeyType::Public, KeyUsage::Encryption>
  : std::array<std::uint8_t, crypto_box_PUBLICKEYBYTES>
{
  TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE_IMPL(AsymmetricKey,
                                        crypto_box_PUBLICKEYBYTES,
                                        PublicEncryptionKey)
};

using PublicEncryptionKey =
    AsymmetricKey<KeyType::Public, KeyUsage::Encryption>;
}
}

namespace std
{
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::PublicEncryptionKey)
}
