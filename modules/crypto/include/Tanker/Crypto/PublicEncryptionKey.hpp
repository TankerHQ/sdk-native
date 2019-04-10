#pragma once

#include <Tanker/Crypto/AsymmetricKey.hpp>
#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>

#include <sodium/crypto_box.h>

namespace Tanker
{
namespace Crypto
{
template <>
class AsymmetricKey<KeyType::Public, KeyUsage::Encryption>
  : public BasicCryptographicType<
        AsymmetricKey<KeyType::Public, KeyUsage::Encryption>,
        crypto_box_PUBLICKEYBYTES>
{
  using base_t::base_t;
};

using PublicEncryptionKey =
    AsymmetricKey<KeyType::Public, KeyUsage::Encryption>;
}
}
