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
#define TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_ATTRIBUTES \
  (recipientPublicEncryptionKey, Crypto::PublicEncryptionKey),   \
      (resourceId, ResourceId),                                  \
      (sealedSymmetricKey, Crypto::SealedSymmetricKey)

class KeyPublishToUser
{
public:
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION_2(
      KeyPublishToUser,
      TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_ATTRIBUTES)

public:
  KeyPublishToUser(
      TrustchainId const& trustchainId,
      Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
      ResourceId const& resourceId,
      Crypto::SealedSymmetricKey const& sealedSymmetricKey,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  static constexpr Nature nature();

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToUser&);
};

constexpr Nature KeyPublishToUser::nature()
{
  return Nature::KeyPublishToUser;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(KeyPublishToUser)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(KeyPublishToUser)
}
}
}
