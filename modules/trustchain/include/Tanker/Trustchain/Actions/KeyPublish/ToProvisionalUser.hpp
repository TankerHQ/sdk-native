#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_PROVISIONAL_USER_ATTRIBUTES                                   \
  (appPublicSignatureKey, Crypto::PublicSignatureKey), (tankerPublicSignatureKey, Crypto::PublicSignatureKey), \
      (resourceId, Crypto::SimpleResourceId), (twoTimesSealedSymmetricKey, Crypto::TwoTimesSealedSymmetricKey)

class KeyPublishToProvisionalUser
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(KeyPublishToProvisionalUser,
                                         TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_PROVISIONAL_USER_ATTRIBUTES)

public:
  KeyPublishToProvisionalUser(TrustchainId const& trustchainId,
                              Crypto::PublicSignatureKey const& appPublicSignatureKey,
                              Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
                              Crypto::SimpleResourceId const& resourceId,
                              Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey,
                              Crypto::Hash const& author,
                              Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

private:
  friend void from_serialized(Serialization::SerializedSource&, KeyPublishToProvisionalUser&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(KeyPublishToProvisionalUser)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(KeyPublishToProvisionalUser)
}
}
}
