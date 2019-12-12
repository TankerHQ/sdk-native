#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

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
              Crypto::Hash const& author,
              Action const& action,
              Crypto::Hash const& hash,
              Crypto::Signature const& signature);

  TrustchainId const& trustchainId() const;
  std::uint64_t const& index() const;
  Crypto::Hash const& author() const;
  Action const& action() const;
  Crypto::Hash const& hash() const;
  Crypto::Signature const& signature() const;

private:
  TrustchainId _trustchainId;
  std::uint64_t _index;
  Crypto::Hash _author;
  Action _action;
  Crypto::Hash _hash;
  Crypto::Signature _signature;

  friend void from_serialized(Serialization::SerializedSource&, ServerEntry&);
};

bool operator==(ServerEntry const& lhs, ServerEntry const& rhs);
bool operator!=(ServerEntry const& lhs, ServerEntry const& rhs);

void from_serialized(Serialization::SerializedSource& ss, ServerEntry& se);

std::vector<ServerEntry> fromBlocksToServerEntries(
    gsl::span<std::string const>);

void to_json(nlohmann::json& j, ServerEntry const& se);
}
}
