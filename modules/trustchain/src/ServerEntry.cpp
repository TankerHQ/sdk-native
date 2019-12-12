#include <Tanker/Trustchain/ServerEntry.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/ComputeHash.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>
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

void from_serialized(Serialization::SerializedSource& ss, ServerEntry& se)
{
  auto const version = ss.read_varint();

  if (version != 1)
  {
    throw Errors::formatEx(
        Errc::InvalidBlockVersion, "unsupported block version: {}", version);
  }
  se._index = ss.read_varint();
  Serialization::deserialize_to(ss, se._trustchainId);
  auto const nature = static_cast<Actions::Nature>(ss.read_varint());

  auto const payloadSize = ss.read_varint();
  auto const payloadSpan = ss.read(payloadSize);

  se._action = Action::deserialize(nature, payloadSpan);
  Serialization::deserialize_to(ss, se._author);
  Serialization::deserialize_to(ss, se._signature);
  se._hash = computeHash(nature, se._author, payloadSpan);
}

void to_json(nlohmann::json& j, ServerEntry const& se)
{
  j["trustchainId"] = se.trustchainId();
  j["index"] = se.index();
  j["author"] = se.author();
  j["action"] = se.action();
  j["hash"] = se.hash();
  j["signature"] = se.signature();
}

std::vector<ServerEntry> fromBlocksToServerEntries(
    gsl::span<std::string const> blocks)
{
  std::vector<ServerEntry> entries;
  entries.reserve(blocks.size());
  std::transform(std::begin(blocks),
                 std::end(blocks),
                 std::back_inserter(entries),
                 [](auto const& block) {
                   return (Serialization::deserialize<Trustchain::ServerEntry>(
                       cppcodec::base64_rfc4648::decode(block)));
                 });
  return entries;
}
}
}
