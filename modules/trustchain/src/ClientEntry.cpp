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
                         Crypto::Hash const& hash,
                         Crypto::Signature const& signature)
  : _trustchainId(trustchainId),
    _parentHash(parentHash),
    _nature(nature),
    _serializedPayload(serializedPayload),
    _hash(hash),
    _signature(signature)
{
}

ClientEntry ClientEntry::create(TrustchainId const& trustchainId,
                                Crypto::Hash const& parentHash,
                                Action const& action,
                                Crypto::PrivateSignatureKey const& key)
{
  auto const serializedPayload = Serialization::serialize(action);

  auto const natureInt = static_cast<unsigned>(action.nature());
  std::vector<std::uint8_t> buffer(Serialization::varint_size(natureInt) +
                                   parentHash.size() +
                                   serializedPayload.size());
  auto it = buffer.data();
  it = Serialization::varint_write(it, natureInt);
  it = Serialization::serialize(it, parentHash);
  std::copy(serializedPayload.begin(), serializedPayload.end(), it);

  auto const hash = Crypto::generichash(buffer);
  auto const signature = Crypto::sign(hash, key);

  return {trustchainId,
          parentHash,
          static_cast<Actions::Nature>(natureInt),
          serializedPayload,
          hash,
          signature};
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

Crypto::Hash const& ClientEntry::hash() const
{
  return _hash;
}

bool operator==(ClientEntry const& lhs, ClientEntry const& rhs)
{
  return lhs.nature() == rhs.nature() &&
         std::tie(lhs.trustchainId(),
                  lhs.parentHash(),
                  lhs.serializedPayload(),
                  lhs.hash(),
                  lhs.signature()) == std::tie(rhs.trustchainId(),
                                               rhs.parentHash(),
                                               rhs.serializedPayload(),
                                               rhs.hash(),
                                               rhs.signature());
}

bool operator!=(ClientEntry const& lhs, ClientEntry const& rhs)
{
  return !(lhs == rhs);
}
}
}
