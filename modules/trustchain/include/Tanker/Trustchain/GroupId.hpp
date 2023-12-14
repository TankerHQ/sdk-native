#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>

namespace Tanker
{
namespace Trustchain
{
class GroupId;
}

namespace Crypto
{
extern template class BasicCryptographicType<Trustchain::GroupId, PublicSignatureKey::arraySize>;
}

namespace Trustchain
{
class GroupId : public Crypto::BasicCryptographicType<GroupId, Crypto::PublicSignatureKey::arraySize>
{
  using base_t::base_t;
};
}
}
