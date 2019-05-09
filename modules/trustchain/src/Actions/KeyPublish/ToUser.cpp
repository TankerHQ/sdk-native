#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToUser::KeyPublishToUser(
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SealedSymmetricKey const& sealedSymmetricKey)
  : _recipientPublicEncryptionKey(recipientPublicEncryptionKey),
    _resourceId(resourceId),
    _sealedSymmetricKey(sealedSymmetricKey)
{
}

Crypto::PublicEncryptionKey const&
KeyPublishToUser::recipientPublicEncryptionKey() const
{
  return _recipientPublicEncryptionKey;
}

ResourceId const& KeyPublishToUser::resourceId() const
{
  return _resourceId;
}

Crypto::SealedSymmetricKey const& KeyPublishToUser::sealedSymmetricKey() const
{
  return _sealedSymmetricKey;
}

bool operator==(KeyPublishToUser const& lhs, KeyPublishToUser const& rhs)
{
  return std::tie(lhs.recipientPublicEncryptionKey(),
                  lhs.resourceId(),
                  lhs.sealedSymmetricKey()) ==
         std::tie(rhs.recipientPublicEncryptionKey(),
                  rhs.resourceId(),
                  rhs.sealedSymmetricKey());
}

bool operator!=(KeyPublishToUser const& lhs, KeyPublishToUser const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss, KeyPublishToUser& kp)
{
  Serialization::deserialize_to(ss, kp._recipientPublicEncryptionKey);
  Serialization::deserialize_to(ss, kp._resourceId);
  Serialization::deserialize_to(ss, kp._sealedSymmetricKey);
}

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToUser const& kp)
{
  it = Serialization::serialize(it, kp.recipientPublicEncryptionKey());
  it = Serialization::serialize(it, kp.resourceId());
  return Serialization::serialize(it, kp.sealedSymmetricKey());
}

void to_json(nlohmann::json& j, KeyPublishToUser const& kp)
{
  j["recipientPublicEncryptionKey"] = kp.recipientPublicEncryptionKey();
  j["resourceId"] = kp.resourceId();
  j["key"] = kp.sealedSymmetricKey();
}
}
}
}
