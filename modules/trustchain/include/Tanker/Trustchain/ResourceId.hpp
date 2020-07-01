#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/Mac.hpp>

#include <cstddef>
#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Trustchain
{
class ResourceId;
}

namespace Crypto
{
extern template class BasicCryptographicType<Trustchain::ResourceId,
                                             Mac::arraySize>;
}

namespace Trustchain
{
class ResourceId
  : public Crypto::BasicCryptographicType<ResourceId, Crypto::Mac::arraySize>
{
  using base_t::base_t;
};
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Trustchain::ResourceId>
  : public integral_constant<size_t,
                             ::Tanker::Trustchain::ResourceId::arraySize>
{
};

template <size_t I>
class tuple_element<I, ::Tanker::Trustchain::ResourceId>
  : public tuple_element<I, ::Tanker::Trustchain::ResourceId::array_t>
{
};
}
