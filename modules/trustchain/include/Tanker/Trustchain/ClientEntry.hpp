#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
class Action;

class ClientEntry
{
public:
  ClientEntry() = default;
  ClientEntry(TrustchainId const& trustchainId,
              Crypto::Hash const& parentHash,
              Actions::Nature nature,
              std::vector<std::uint8_t> serializedPayload,
              Crypto::Signature const& signature);
  ClientEntry(TrustchainId const& trustchainId,
              Crypto::Hash const& parentHash,
              Actions::Nature nature,
              std::vector<std::uint8_t> serializedPayload);

  static ClientEntry create(TrustchainId const&,
                            Crypto::Hash const&,
                            Action const&,
                            Crypto::PrivateSignatureKey const&);

  TrustchainId const& trustchainId() const;
  Crypto::Hash const& parentHash() const;
  Actions::Nature nature() const;
  std::vector<std::uint8_t> const& serializedPayload() const;
  Crypto::Signature const& signature() const;

  Crypto::Hash hash() const;
  Crypto::Signature const& sign(Crypto::PrivateSignatureKey const&);

private:
  TrustchainId _trustchainId;
  Crypto::Hash _parentHash;
  Actions::Nature _nature;
  std::vector<std::uint8_t> _serializedPayload;
  Crypto::Signature _signature;
};

bool operator==(ClientEntry const& lhs, ClientEntry const& rhs);
bool operator!=(ClientEntry const& lhs, ClientEntry const& rhs);
}
}

#include <Tanker/Trustchain/Json/ClientEntry.hpp>
#include <Tanker/Trustchain/Serialization/ClientEntry.hpp>
