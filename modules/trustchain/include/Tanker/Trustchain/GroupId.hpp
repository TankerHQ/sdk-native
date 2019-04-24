#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>

#include <cstddef>
#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Trustchain
{
class GroupId;
}

namespace Crypto
{
extern template class BasicCryptographicType<Trustchain::GroupId,
                                             PublicSignatureKey::arraySize>;
}

namespace Trustchain
{
class GroupId
  : public Crypto::BasicCryptographicType<GroupId,
                                          Crypto::PublicSignatureKey::arraySize>
{
  using base_t::base_t;
};
}
}

// Required for cppcodec array-like types support
namespace std
{
template <>
class tuple_size<::Tanker::Trustchain::GroupId>
  : public integral_constant<size_t, ::Tanker::Trustchain::GroupId::arraySize>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::Trustchain::GroupId>
  : public tuple_element<I, ::Tanker::Trustchain::GroupId::array_t>
{
};
}
