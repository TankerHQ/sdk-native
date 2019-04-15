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
    class EncryptedSymmetricKey,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_box_MACBYTES +
        crypto_box_NONCEBYTES>;

class EncryptedSymmetricKey
  : public BasicCryptographicType<EncryptedSymmetricKey,
                                  crypto_aead_xchacha20poly1305_ietf_KEYBYTES +
                                      crypto_box_MACBYTES +
                                      crypto_box_NONCEBYTES>
{
  using base_t::base_t;
};
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Crypto::EncryptedSymmetricKey>
  : public integral_constant<size_t,
                             crypto_aead_xchacha20poly1305_ietf_KEYBYTES +
                                 crypto_box_MACBYTES + crypto_box_NONCEBYTES>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::Crypto::EncryptedSymmetricKey>
  : public tuple_element<I,
                         ::Tanker::Crypto::EncryptedSymmetricKey::base_t>
{
};
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
