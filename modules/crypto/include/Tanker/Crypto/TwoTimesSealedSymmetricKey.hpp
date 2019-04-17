#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>

#include <sodium/crypto_box.h>

#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
// Yes, the name is weird... This will be replaced by a Sealed<> class template
// later on.
extern template class BasicCryptographicType<class TwoTimesSealedSymmetricKey,
                                             crypto_box_SEALBYTES +
                                                 SealedSymmetricKey::arraySize>;

class TwoTimesSealedSymmetricKey
  : public BasicCryptographicType<TwoTimesSealedSymmetricKey,
                                  crypto_box_SEALBYTES +
                                      SealedSymmetricKey::arraySize>
{
  using base_t::base_t;
};
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Crypto::TwoTimesSealedSymmetricKey>
  : public integral_constant<
        size_t,
        ::Tanker::Crypto::TwoTimesSealedSymmetricKey::arraySize>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::Crypto::TwoTimesSealedSymmetricKey>
  : public tuple_element<I,
                         ::Tanker::Crypto::TwoTimesSealedSymmetricKey::base_t>
{
};
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
