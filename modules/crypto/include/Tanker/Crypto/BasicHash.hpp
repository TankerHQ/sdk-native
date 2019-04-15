#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>

#include <sodium/crypto_generichash.h>

namespace Tanker
{
namespace Crypto
{
template <typename Unused>
class BasicHash;

extern template class BasicCryptographicType<BasicHash<void>,
                                             crypto_generichash_BYTES>;

template <>
class BasicHash<void>
  : public BasicCryptographicType<BasicHash<void>, crypto_generichash_BYTES>
{
  using base_t::base_t;
};

template <typename Unused>
class BasicHash
  : public BasicCryptographicType<BasicHash<Unused>, crypto_generichash_BYTES>
{
  using BasicHash::BasicCryptographicType::BasicCryptographicType;

public:
  BasicHash() = default;
  explicit BasicHash(BasicHash<void> const& rhs)
  {
    this->base() = rhs.base();
  }
};

extern template class BasicHash<void>;
}
}

namespace std
{
template <typename Unused>
class tuple_size<::Tanker::Crypto::BasicHash<Unused>>
  : public tuple_size<typename ::Tanker::Crypto::BasicHash<Unused>::base_t>
{
};

template <std::size_t I, typename Unused>
class tuple_element<I, ::Tanker::Crypto::BasicHash<Unused>>
  : public tuple_element<I,
                         typename ::Tanker::Crypto::BasicHash<Unused>::base_t>
{
};
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
