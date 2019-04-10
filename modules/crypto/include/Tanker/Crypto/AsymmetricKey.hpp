#pragma once

#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>

#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
template <KeyType Type, KeyUsage Usage>
class AsymmetricKey;
}
}

namespace std
{
template <::Tanker::Crypto::KeyType KT, ::Tanker::Crypto::KeyUsage KU>
class tuple_size<::Tanker::Crypto::AsymmetricKey<KT, KU>>
  : public integral_constant<size_t,
                             ::Tanker::Crypto::AsymmetricKey<KT, KU>::arraySize>
{
};

template <size_t I, ::Tanker::Crypto::KeyType KT, ::Tanker::Crypto::KeyUsage KU>
class tuple_element<I, ::Tanker::Crypto::AsymmetricKey<KT, KU>>
  : public tuple_element<
        I,
        typename ::Tanker::Crypto::AsymmetricKey<KT, KU>::base_t>
{
};
}
