#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
class ServerEntry
{
public:
  ServerEntry() = default;
  ServerEntry(TrustchainId const& trustchainId,
              std::uint64_t index,
              Crypto::Hash const& parentHash,
              Action const& action,
              Crypto::Hash const& hash,
              Crypto::Signature const& signature);

  TrustchainId const& trustchainId() const;
  std::uint64_t const& index() const;
  Crypto::Hash const& parentHash() const;
  Action const& action() const;
  Crypto::Hash const& hash() const;
  Crypto::Signature const& signature() const;

private:
  TrustchainId _trustchainId;
  std::uint64_t _index;
  Crypto::Hash _parentHash;
  Action _action;
  Crypto::Hash _hash;
  Crypto::Signature _signature;

  friend void from_serialized(Serialization::SerializedSource&, ServerEntry&);
};

bool operator==(ServerEntry const& lhs, ServerEntry const& rhs);
bool operator!=(ServerEntry const& lhs, ServerEntry const& rhs);
}
}

#include <Tanker/Trustchain/Serialization/ServerEntry.hpp>
#include <Tanker/Trustchain/Json/ServerEntry.hpp>
