#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>

#include <sodium/crypto_box.h>

#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
class SealedPrivateEncryptionKey
  : public BasicCryptographicType<SealedPrivateEncryptionKey,
                                  crypto_box_SECRETKEYBYTES +
                                      crypto_box_SEALBYTES>
{
  using base_t::base_t;
};
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Crypto::SealedPrivateEncryptionKey>
  : public integral_constant<size_t,
                             crypto_box_SECRETKEYBYTES + crypto_box_SEALBYTES>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::Crypto::SealedPrivateEncryptionKey>
  : public tuple_element<I,
                         ::Tanker::Crypto::SealedPrivateEncryptionKey::base_t>
{
};
}
