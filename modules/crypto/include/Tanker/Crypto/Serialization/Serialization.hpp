#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>
#include <Tanker/Crypto/KeyPair.hpp>

#include <Tanker/Serialization/SerializedSource.hpp>

#include <range/v3/algorithm/copy.hpp>

#include <algorithm>
#include <cstdint>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
template <typename T, typename = std::enable_if_t<IsCryptographicType<T>::value>>
constexpr std::size_t serialized_size(T const&)
{
  return T::arraySize;
}

template <typename T, typename = std::enable_if_t<IsCryptographicType<T>::value>>
void from_serialized(Serialization::SerializedSource& ss, T& val)
{
  auto sp = ss.read(T::arraySize);
  std::copy(sp.begin(), sp.end(), val.begin());
}

template <typename T, typename = std::enable_if_t<IsCryptographicType<T>::value>>
std::uint8_t* to_serialized(std::uint8_t* it, T const& val)
{
  return std::copy(val.begin(), val.end(), it);
}

template <KeyUsage Usage>
constexpr std::size_t serialized_size(KeyPair<Usage> const&)
{
  return AsymmetricKey<KeyType::Public, Usage>::arraySize + AsymmetricKey<KeyType::Private, Usage>::arraySize;
}

template <KeyUsage Usage>
void from_serialized(Serialization::SerializedSource& ss, KeyPair<Usage>& val)
{
  auto sp = ss.read(AsymmetricKey<KeyType::Public, Usage>::arraySize);
  ranges::copy(sp, val.publicKey.begin());
  sp = ss.read(AsymmetricKey<KeyType::Private, Usage>::arraySize);
  ranges::copy(sp, val.privateKey.begin());
}

template <KeyUsage Usage>
std::uint8_t* to_serialized(std::uint8_t* it, KeyPair<Usage> const& val)
{
  it = std::copy(val.publicKey.begin(), val.publicKey.end(), it);
  it = std::copy(val.privateKey.begin(), val.privateKey.end(), it);
  return it;
}
}
}
