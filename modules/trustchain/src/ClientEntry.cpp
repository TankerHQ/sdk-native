#include <Tanker/Trustchain/ClientEntry.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>

#include <algorithm>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
ClientEntry::ClientEntry(TrustchainId const& trustchainId,
                         Crypto::Hash const& parentHash,
                         Actions::Nature nature,
                         std::vector<std::uint8_t> serializedPayload,
                         Crypto::Signature const& signature)
  : _trustchainId(trustchainId),
    _parentHash(parentHash),
    _nature(nature),
    _serializedPayload(serializedPayload),
    _signature(signature)
{
}

ClientEntry::ClientEntry(TrustchainId const& trustchainId,
                         Crypto::Hash const& parentHash,
                         Actions::Nature nature,
                         std::vector<std::uint8_t> serializedPayload)
  : _trustchainId(trustchainId),
    _parentHash(parentHash),
    _nature(nature),
    _serializedPayload(serializedPayload)
{
}

ClientEntry ClientEntry::create(TrustchainId const& trustchainId,
                                Crypto::Hash const& parentHash,
                                Action const& action,
                                Crypto::PrivateSignatureKey const& key)
{
  ClientEntry entry{trustchainId,
                    parentHash,
                    action.nature(),
                    Serialization::serialize(action)};
  entry.sign(key);
  return entry;
}

TrustchainId const& ClientEntry::trustchainId() const
{
  return _trustchainId;
}

Crypto::Hash const& ClientEntry::parentHash() const
{
  return _parentHash;
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

Crypto::Hash ClientEntry::hash() const
{
  auto const natureInt = static_cast<unsigned>(nature());

  std::vector<std::uint8_t> buffer(Serialization::varint_size(natureInt) +
                                   _parentHash.size() +
                                   _serializedPayload.size());
  auto it = buffer.data();
  it = Serialization::varint_write(it, natureInt);
  it = Serialization::serialize(it, _parentHash);
  std::copy(_serializedPayload.begin(), _serializedPayload.end(), it);

  return Crypto::generichash(buffer);
}

Crypto::Signature const& ClientEntry::sign(
    Crypto::PrivateSignatureKey const& key)
{
  return _signature = Crypto::sign(hash(), key);
}

bool operator==(ClientEntry const& lhs, ClientEntry const& rhs)
{
  return lhs.nature() == rhs.nature() &&
         std::tie(lhs.trustchainId(),
                  lhs.parentHash(),
                  lhs.serializedPayload(),
                  lhs.signature()) == std::tie(rhs.trustchainId(),
                                               rhs.parentHash(),
                                               rhs.serializedPayload(),
                                               rhs.signature());
}

bool operator!=(ClientEntry const& lhs, ClientEntry const& rhs)
{
  return !(lhs == rhs);
}
}
}
