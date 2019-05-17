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

namespace std
{
template <typename T>
class tuple_size<::Tanker::Crypto::Sealed<T>>
  : public integral_constant<size_t, ::Tanker::Crypto::Sealed<T>::arraySize>
{
};

template <size_t I, typename T>
class tuple_element<I, ::Tanker::Crypto::Sealed<T>>
  : public tuple_element<I, typename ::Tanker::Crypto::Sealed<T>::base_t>
{
};
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
