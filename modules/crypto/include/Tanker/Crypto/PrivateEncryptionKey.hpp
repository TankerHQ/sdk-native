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
extern template class BasicCryptographicType<AsymmetricKey<KeyType::Private, KeyUsage::Encryption>,
                                             crypto_box_SECRETKEYBYTES>;

template <>
class AsymmetricKey<KeyType::Private, KeyUsage::Encryption>
  : public BasicCryptographicType<AsymmetricKey<KeyType::Private, KeyUsage::Encryption>, crypto_box_SECRETKEYBYTES>
{
  using base_t::base_t;
};

extern template class AsymmetricKey<KeyType::Private, KeyUsage::Encryption>;

using PrivateEncryptionKey = AsymmetricKey<KeyType::Private, KeyUsage::Encryption>;
}
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
