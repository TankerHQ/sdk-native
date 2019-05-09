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
class KeyPublishToUserGroup
{
public:
  KeyPublishToUserGroup() = default;
  KeyPublishToUserGroup(Crypto::PublicEncryptionKey const&,
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
                              KeyPublishToUserGroup&);
};

bool operator==(KeyPublishToUserGroup const&, KeyPublishToUserGroup const&);
bool operator!=(KeyPublishToUserGroup const&, KeyPublishToUserGroup const&);

void from_serialized(Serialization::SerializedSource&, KeyPublishToUserGroup&);
std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToUserGroup const&);

constexpr std::size_t serialized_size(KeyPublishToUserGroup const&)
{
  return Crypto::PublicEncryptionKey::arraySize + ResourceId::arraySize +
         Crypto::SealedSymmetricKey::arraySize;
}

void to_json(nlohmann::json&, KeyPublishToUserGroup const&);

constexpr Nature KeyPublishToUserGroup::nature()
{
  return Nature::KeyPublishToUserGroup;
}
}
}
}
