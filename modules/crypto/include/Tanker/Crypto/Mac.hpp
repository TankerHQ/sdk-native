#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>

#include <sodium/crypto_aead_xchacha20poly1305.h>

#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
extern template class BasicCryptographicType<
    class Mac,
    crypto_aead_xchacha20poly1305_ietf_ABYTES>;

class Mac
  : public BasicCryptographicType<Mac,
                                  crypto_aead_xchacha20poly1305_ietf_ABYTES>
{
  using base_t::base_t;
};
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Crypto::Mac>
  : public integral_constant<size_t, crypto_aead_xchacha20poly1305_ietf_ABYTES>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::Crypto::Mac>
  : public tuple_element<I, ::Tanker::Crypto::Mac::base_t>
{
};
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
