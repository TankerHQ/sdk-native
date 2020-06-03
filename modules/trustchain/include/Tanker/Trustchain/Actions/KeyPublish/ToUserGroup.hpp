#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_GROUP_ATTRIBUTES \
  (recipientPublicEncryptionKey, Crypto::PublicEncryptionKey),         \
      (resourceId, ResourceId),                                        \
      (sealedSymmetricKey, Crypto::SealedSymmetricKey)

class KeyPublishToUserGroup
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      KeyPublishToUserGroup,
      TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_GROUP_ATTRIBUTES)

public:
  KeyPublishToUserGroup(
      TrustchainId const& trustchainId,
      Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
      ResourceId const& resourceId,
      Crypto::SealedSymmetricKey const& sealedSymmetricKey,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToUserGroup&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(KeyPublishToUserGroup)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(KeyPublishToUserGroup)
}
}
}
