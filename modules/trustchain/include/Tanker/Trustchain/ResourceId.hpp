#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/Mac.hpp>

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
