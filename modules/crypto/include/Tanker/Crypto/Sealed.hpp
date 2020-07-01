#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>

#include <sodium/crypto_box.h>

namespace Tanker
{
namespace Crypto
{
template <typename T>
class Sealed
  : public BasicCryptographicType<Sealed<T>,
                                  T::arraySize + crypto_box_SEALBYTES>
{
  using BasicCryptographicType<Sealed<T>, Sealed<T>::arraySize>::base_t::base_t;
};
}
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
