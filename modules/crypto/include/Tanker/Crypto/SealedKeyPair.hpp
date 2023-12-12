#pragma once

#include <Tanker/Crypto/AsymmetricKey.hpp>
#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/Sealed.hpp>

#include <tuple>

namespace Tanker::Crypto
{
template <KeyUsage Usage>
struct SealedKeyPair
{
  AsymmetricKey<KeyType::Public, Usage> publicKey;
  Sealed<AsymmetricKey<KeyType::Private, Usage>> sealedPrivateKey;
};

template <KeyUsage Usage>
bool operator==(SealedKeyPair<Usage> const& a, SealedKeyPair<Usage> const& b)
{
  return std::tie(a.publicKey, a.sealedPrivateKey) == std::tie(b.publicKey, b.sealedPrivateKey);
}

template <KeyUsage Usage>
bool operator!=(SealedKeyPair<Usage> const& a, SealedKeyPair<Usage> const& b)
{
  return !(a == b);
}
}
