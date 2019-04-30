#include <Tanker/Trustchain/ServerEntry.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/detail/ComputeHash.hpp>

#include <algorithm>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
ServerEntry::ServerEntry(TrustchainId const& trustchainId,
                         std::uint64_t index,
                         Crypto::Hash const& parentHash,
                         Action const& action,
                         Crypto::Hash const& hash,
                         Crypto::Signature const& signature)
  : _trustchainId(trustchainId),
    _index(index),
    _parentHash(parentHash),
    _action(action),
    _hash(hash),
    _signature(signature)
{
}

TrustchainId const& ServerEntry::trustchainId() const
{
  return _trustchainId;
}

std::uint64_t const& ServerEntry::index() const
{
  return _index;
}

Crypto::Hash const& ServerEntry::parentHash() const
{
  return _parentHash;
}

Action const& ServerEntry::action() const
{
  return _action;
}

Crypto::Signature const& ServerEntry::signature() const
{
  return _signature;
}

Crypto::Hash const& ServerEntry::hash() const
{
  return _hash;
}

bool operator==(ServerEntry const& lhs, ServerEntry const& rhs)
{
  return lhs.index() == rhs.index() &&
         std::tie(lhs.trustchainId(),
                  lhs.parentHash(),
                  lhs.action(),
                  lhs.hash(),
                  lhs.signature()) == std::tie(rhs.trustchainId(),
                                               rhs.parentHash(),
                                               rhs.action(),
                                               rhs.hash(),
                                               rhs.signature());
}

bool operator!=(ServerEntry const& lhs, ServerEntry const& rhs)
{
  return !(lhs == rhs);
}
}
}
