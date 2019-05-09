#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToUserGroup::KeyPublishToUserGroup(
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SealedSymmetricKey const& sealedSymmetricKey)
  : _recipientPublicEncryptionKey(recipientPublicEncryptionKey),
    _resourceId(resourceId),
    _sealedSymmetricKey(sealedSymmetricKey)
{
}

Crypto::PublicEncryptionKey const&
KeyPublishToUserGroup::recipientPublicEncryptionKey() const
{
  return _recipientPublicEncryptionKey;
}

ResourceId const& KeyPublishToUserGroup::resourceId() const
{
  return _resourceId;
}

Crypto::SealedSymmetricKey const& KeyPublishToUserGroup::sealedSymmetricKey()
    const
{
  return _sealedSymmetricKey;
}

bool operator==(KeyPublishToUserGroup const& lhs,
                KeyPublishToUserGroup const& rhs)
{
  return std::tie(lhs.recipientPublicEncryptionKey(),
                  lhs.resourceId(),
                  lhs.sealedSymmetricKey()) ==
         std::tie(rhs.recipientPublicEncryptionKey(),
                  rhs.resourceId(),
                  rhs.sealedSymmetricKey());
}

bool operator!=(KeyPublishToUserGroup const& lhs,
                KeyPublishToUserGroup const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss,
                     KeyPublishToUserGroup& kp)
{
  Serialization::deserialize_to(ss, kp._recipientPublicEncryptionKey);
  Serialization::deserialize_to(ss, kp._resourceId);
  Serialization::deserialize_to(ss, kp._sealedSymmetricKey);
}

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToUserGroup const& kp)
{
  it = Serialization::serialize(it, kp.recipientPublicEncryptionKey());
  it = Serialization::serialize(it, kp.resourceId());
  return Serialization::serialize(it, kp.sealedSymmetricKey());
}

void to_json(nlohmann::json& j, KeyPublishToUserGroup const& kp)
{
  j["recipientPublicEncryptionKey"] = kp.recipientPublicEncryptionKey();
  j["resourceId"] = kp.resourceId();
  j["key"] = kp.sealedSymmetricKey();
}
}
}
}
