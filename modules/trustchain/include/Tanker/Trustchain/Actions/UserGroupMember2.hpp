#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/UserId.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_MEMBER_V2_ATTRIBUTES \
  (userId, UserId), (userPublicKey, Crypto::PublicEncryptionKey), \
      (encryptedPrivateEncryptionKey, Crypto::SealedPrivateEncryptionKey)

class UserGroupMember2
{
  TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(
      UserGroupMember2,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_MEMBER_V2_ATTRIBUTES)

  friend void from_serialized(Serialization::SerializedSource& ss,
                              UserGroupMember2& k);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupMember2)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupMember2)
}
}
}
