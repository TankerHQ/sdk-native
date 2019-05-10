#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToUser
{
public:
  KeyPublishToUser() = default;
  KeyPublishToUser(Crypto::PublicEncryptionKey const&,
                   ResourceId const&,
                   Crypto::SealedSymmetricKey const&);

  static constexpr Nature nature();

  Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey() const;
  ResourceId const& resourceId() const;
  Crypto::SealedSymmetricKey const& sealedSymmetricKey() const;

private:
  Crypto::PublicEncryptionKey _recipientPublicEncryptionKey;
  ResourceId _resourceId;
  Crypto::SealedSymmetricKey _sealedSymmetricKey;

  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToUser&);
};

bool operator==(KeyPublishToUser const&, KeyPublishToUser const&);
bool operator!=(KeyPublishToUser const&, KeyPublishToUser const&);

void from_serialized(Serialization::SerializedSource&, KeyPublishToUser&);
std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToUser const&);

constexpr std::size_t serialized_size(KeyPublishToUser const&)
{
  return Crypto::PublicEncryptionKey::arraySize + ResourceId::arraySize +
         Crypto::SealedSymmetricKey::arraySize;
}

void to_json(nlohmann::json&, KeyPublishToUser const&);

constexpr Nature KeyPublishToUser::nature()
{
  return Nature::KeyPublishToUser;
}
}
}
}
