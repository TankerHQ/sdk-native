#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>
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
#define TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_PROVISIONAL_USER_ATTRIBUTES \
  (appPublicSignatureKey, Crypto::PublicSignatureKey),                       \
      (tankerPublicSignatureKey, Crypto::PublicSignatureKey),                \
      (resourceId, ResourceId),                                              \
      (twoTimesSealedSymmetricKey, Crypto::TwoTimesSealedSymmetricKey)

class KeyPublishToProvisionalUser
{
public:
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION_2(
      KeyPublishToProvisionalUser,
      TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_PROVISIONAL_USER_ATTRIBUTES)

public:
  KeyPublishToProvisionalUser(
      TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& appPublicSignatureKey,
      Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
      ResourceId const& resourceId,
      Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToProvisionalUser&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(KeyPublishToProvisionalUser)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(KeyPublishToProvisionalUser)
}
}
}
