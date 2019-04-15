#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>

#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>

#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
extern template class BasicCryptographicType<
    class SealedSymmetricKey,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_box_SEALBYTES>;

class SealedSymmetricKey
  : public BasicCryptographicType<SealedSymmetricKey,
                                  crypto_aead_xchacha20poly1305_ietf_KEYBYTES +
                                      crypto_box_SEALBYTES>
{
  using base_t::base_t;
};
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Crypto::SealedSymmetricKey>
  : public integral_constant<size_t,
                             crypto_aead_xchacha20poly1305_ietf_KEYBYTES +
                                 crypto_box_SEALBYTES>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::Crypto::SealedSymmetricKey>
  : public tuple_element<I, ::Tanker::Crypto::SealedSymmetricKey::base_t>
{
};
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
