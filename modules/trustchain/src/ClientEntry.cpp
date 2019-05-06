#include <Tanker/Trustchain/ClientEntry.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/detail/ComputeHash.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
ClientEntry::ClientEntry(TrustchainId const& trustchainId,
                         Crypto::Hash const& author,
                         Actions::Nature nature,
                         std::vector<std::uint8_t> serializedPayload,
                         Crypto::Hash const& hash,
                         Crypto::Signature const& signature)
  : _trustchainId(trustchainId),
    _author(author),
    _nature(nature),
    _serializedPayload(serializedPayload),
    _hash(hash),
    _signature(signature)
{
}

ClientEntry ClientEntry::create(TrustchainId const& trustchainId,
                                Crypto::Hash const& author,
                                Action const& action,
                                Crypto::PrivateSignatureKey const& key)
{
  auto const serializedPayload = Serialization::serialize(action);
  auto const hash =
      detail::computeHash(action.nature(), author, serializedPayload);
  auto const signature = Crypto::sign(hash, key);

  return {trustchainId,
          author,
          action.nature(),
          serializedPayload,
          hash,
          signature};
}

TrustchainId const& ClientEntry::trustchainId() const
{
  return _trustchainId;
}

Crypto::Hash const& ClientEntry::author() const
{
  return _author;
}

Actions::Nature ClientEntry::nature() const
{
  return _nature;
}

std::vector<std::uint8_t> const& ClientEntry::serializedPayload() const
{
  return _serializedPayload;
}

Crypto::Signature const& ClientEntry::signature() const
{
  return _signature;
}

Crypto::Hash const& ClientEntry::hash() const
{
  return _hash;
}

bool operator==(ClientEntry const& lhs, ClientEntry const& rhs)
{
  return lhs.nature() == rhs.nature() &&
         std::tie(lhs.trustchainId(),
                  lhs.author(),
                  lhs.serializedPayload(),
                  lhs.hash(),
                  lhs.signature()) == std::tie(rhs.trustchainId(),
                                               rhs.author(),
                                               rhs.serializedPayload(),
                                               rhs.hash(),
                                               rhs.signature());
}

bool operator!=(ClientEntry const& lhs, ClientEntry const& rhs)
{
  return !(lhs == rhs);
}

std::uint8_t* to_serialized(std::uint8_t* it, ClientEntry const& ce)
{
  auto const natureInt = static_cast<unsigned>(ce.nature());
  auto const version = 1;

  it = Serialization::varint_write(it, version);
  it = Serialization::varint_write(it, std::uint64_t{});
  it = Serialization::serialize(it, ce.trustchainId());
  it = Serialization::varint_write(it, natureInt);
  auto const& serializedPayload = ce.serializedPayload();
  it = Serialization::varint_write(it, serializedPayload.size());
  it = std::copy(serializedPayload.begin(), serializedPayload.end(), it);
  it = Serialization::serialize(it, ce.author());
  return Serialization::serialize(it, ce.signature());
}

std::size_t serialized_size(ClientEntry const& ce)
{
  auto const version = 1;
  auto const natureInt = static_cast<unsigned>(ce.nature());
  // we do not care about the block index client-side
  // but we must put it in the wire format
  std::uint64_t const index{};
  auto const payloadSize = ce.serializedPayload().size();

  return Serialization::varint_size(version) +
         Serialization::varint_size(index) +
         Serialization::varint_size(natureInt) +
         Serialization::varint_size(payloadSize) + TrustchainId::arraySize +
         payloadSize + Crypto::Hash::arraySize + Crypto::Signature::arraySize;
}

void to_json(nlohmann::json& j, ClientEntry const& ce)
{
  j["trustchainId"] = ce.trustchainId();
  j["author"] = ce.author();
  j["nature"] = ce.nature();
  j["serializedPayload"] =
      cppcodec::base64_rfc4648::encode(ce.serializedPayload());
  j["signature"] = ce.signature();
  j["hash"] = ce.hash();
}
}
}
