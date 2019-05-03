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
                         Crypto::Hash const& author,
                         Action const& action,
                         Crypto::Hash const& hash,
                         Crypto::Signature const& signature)
  : _trustchainId(trustchainId),
    _index(index),
    _author(author),
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

Crypto::Hash const& ServerEntry::author() const
{
  return _author;
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
                  lhs.author(),
                  lhs.action(),
                  lhs.hash(),
                  lhs.signature()) == std::tie(rhs.trustchainId(),
                                               rhs.author(),
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
