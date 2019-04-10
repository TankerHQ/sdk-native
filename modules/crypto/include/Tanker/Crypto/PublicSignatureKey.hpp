#pragma once

#include <Tanker/Crypto/AsymmetricKey.hpp>
#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>

#include <sodium/crypto_sign.h>

namespace Tanker
{
namespace Crypto
{
template <>
class AsymmetricKey<KeyType::Public, KeyUsage::Signature>
  : public BasicCryptographicType<
        AsymmetricKey<KeyType::Public, KeyUsage::Signature>,
        crypto_sign_PUBLICKEYBYTES>
{
  using base_t::base_t;
};

using PublicSignatureKey =
    AsymmetricKey<KeyType::Public, KeyUsage::Signature>;
}
}
