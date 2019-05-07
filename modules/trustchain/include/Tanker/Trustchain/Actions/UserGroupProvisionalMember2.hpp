#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_PROVISIONAL_MEMBER_V2_ATTRIBUTES \
  (appPublicSignatureKey, Crypto::PublicSignatureKey),                        \
      (tankerPublicSignatureKey, Crypto::PublicSignatureKey),                 \
      (encryptedPrivateEncryptionKey,                                         \
       Crypto::TwoTimesSealedPrivateEncryptionKey)

class UserGroupProvisionalMember2
{
  TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(
      UserGroupProvisionalMember2,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_PROVISIONAL_MEMBER_V2_ATTRIBUTES)

  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupProvisionalMember2&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupProvisionalMember2)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupProvisionalMember2)
}
}
}
