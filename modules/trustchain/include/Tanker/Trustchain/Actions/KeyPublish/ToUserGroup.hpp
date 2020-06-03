#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/Serialization.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

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
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION_2(
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
