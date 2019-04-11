#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>

#include <Tanker/Serialization/SerializedSource.hpp>

#include <algorithm>
#include <cstdint>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
template <typename T,
          typename = std::enable_if_t<IsCryptographicType<T>::value>>
constexpr std::size_t serialized_size(T const&)
{
  return T::arraySize;
}

template <typename T,
          typename = std::enable_if_t<IsCryptographicType<T>::value>>
void from_serialized(Serialization::SerializedSource& ss, T& val)
{
  auto sp = ss.read(T::arraySize);
  std::copy(sp.begin(), sp.end(), val.begin());
}

template <typename T,
          typename = std::enable_if_t<IsCryptographicType<T>::value>>
std::uint8_t* to_serialized(std::uint8_t* it, T const& val)
{
  return std::copy(val.begin(), val.end(), it);
}
}
}
