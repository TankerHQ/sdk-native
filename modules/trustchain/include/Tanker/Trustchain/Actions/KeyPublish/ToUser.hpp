#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_ATTRIBUTES \
  (recipientPublicEncryptionKey, Crypto::PublicEncryptionKey),   \
      (resourceId, Crypto::SimpleResourceId),                    \
      (sealedSymmetricKey, Crypto::SealedSymmetricKey)

class KeyPublishToUser
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      KeyPublishToUser,
      TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_ATTRIBUTES)

public:
  KeyPublishToUser(
      TrustchainId const& trustchainId,
      Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
      Crypto::SimpleResourceId const& resourceId,
      Crypto::SealedSymmetricKey const& sealedSymmetricKey,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToUser&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(KeyPublishToUser)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(KeyPublishToUser)
}
}
}
