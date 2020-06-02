#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
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
#define TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_ATTRIBUTES \
  (recipientPublicEncryptionKey, Crypto::PublicEncryptionKey),   \
      (resourceId, ResourceId),                                  \
      (sealedSymmetricKey, Crypto::SealedSymmetricKey)

class KeyPublishToUser
{
public:
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION(
      KeyPublishToUser,
      TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_ATTRIBUTES)

public:
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
