#pragma once

#include <Tanker/Crypto/AsymmetricKey.hpp>
#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>

#include <tuple>

namespace Tanker
{
namespace Crypto
{
template <KeyUsage Usage>
struct KeyPair
{
  AsymmetricKey<KeyType::Public, Usage> publicKey;
  AsymmetricKey<KeyType::Private, Usage> privateKey;
};

template <KeyUsage Usage>
bool operator==(KeyPair<Usage> const& a, KeyPair<Usage> const& b)
{
  return std::tie(a.publicKey, a.privateKey) ==
         std::tie(b.publicKey, b.privateKey);
}

template <KeyUsage Usage>
bool operator!=(KeyPair<Usage> const& a, KeyPair<Usage> const& b)
{
  return !(a == b);
}

template <KeyUsage Usage>
bool operator<(KeyPair<Usage> const& a, KeyPair<Usage> const& b)
{
  return a.publicKey() < b.publicKey();
}
}
}
