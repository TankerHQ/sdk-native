#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>

#include <cstddef>
#include <tuple>
#include <type_traits>

namespace Tanker
{
class GroupId
  : public Crypto::BasicCryptographicType<GroupId,
                                          Crypto::PublicSignatureKey::arraySize>
{
  using base_t::base_t;
};
}

// Required for cppcodec array-like types support
namespace std
{
template <>
class tuple_size<::Tanker::GroupId>
  : public integral_constant<size_t, ::Tanker::GroupId::arraySize>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::GroupId>
  : public tuple_element<I, ::Tanker::GroupId::array_t>
{
};
}
