#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>

#include <sodium/crypto_box.h>

#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
// Yes, the name is weird... This will be replaced by a Sealed<> class template
// later on.
extern template class BasicCryptographicType<
    class TwoTimesSealedPrivateEncryptionKey,
    crypto_box_SEALBYTES * 2 + PrivateEncryptionKey::arraySize>;

class TwoTimesSealedPrivateEncryptionKey
  : public BasicCryptographicType<TwoTimesSealedPrivateEncryptionKey,
                                  crypto_box_SEALBYTES * 2 +
                                      PrivateEncryptionKey::arraySize>
{
  using base_t::base_t;
};
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Crypto::TwoTimesSealedPrivateEncryptionKey>
  : public integral_constant<
        size_t,
        ::Tanker::Crypto::TwoTimesSealedPrivateEncryptionKey::arraySize>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::Crypto::TwoTimesSealedPrivateEncryptionKey>
  : public tuple_element<
        I,
        ::Tanker::Crypto::TwoTimesSealedPrivateEncryptionKey::base_t>
{
};
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
