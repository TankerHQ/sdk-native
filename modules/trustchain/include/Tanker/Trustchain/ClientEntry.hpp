#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
class Action;

class [[nodiscard]] ClientEntry
{
public:
  ClientEntry() = default;
  ClientEntry(TrustchainId const& trustchainId,
              Crypto::Hash const& author,
              Actions::Nature nature,
              std::vector<std::uint8_t> serializedPayload,
              Crypto::Hash const& hash,
              Crypto::Signature const& signature);

  static ClientEntry create(TrustchainId const&,
                            Crypto::Hash const&,
                            Action const&,
                            Crypto::PrivateSignatureKey const&);

  TrustchainId const& trustchainId() const;
  Crypto::Hash const& author() const;
  Actions::Nature nature() const;
  std::vector<std::uint8_t> const& serializedPayload() const;
  Crypto::Hash const& hash() const;
  Crypto::Signature const& signature() const;

private:
  TrustchainId _trustchainId;
  Crypto::Hash _author;
  Actions::Nature _nature;
  std::vector<std::uint8_t> _serializedPayload;
  Crypto::Hash _hash;
  Crypto::Signature _signature;
};

bool operator==(ClientEntry const& lhs, ClientEntry const& rhs);
bool operator!=(ClientEntry const& lhs, ClientEntry const& rhs);

std::uint8_t* to_serialized(std::uint8_t*, ClientEntry const&);
std::size_t serialized_size(ClientEntry const&);

void to_json(nlohmann::json&, ClientEntry const&);
}
}
