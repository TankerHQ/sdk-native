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
class AsymmetricKey<KeyType::Private, KeyUsage::Encryption>
  : public BasicCryptographicType<
        AsymmetricKey<KeyType::Private, KeyUsage::Encryption>,
        crypto_box_SECRETKEYBYTES>
{
  using base_t::base_t;
};

using PrivateEncryptionKey =
    AsymmetricKey<KeyType::Private, KeyUsage::Encryption>;
}
}
