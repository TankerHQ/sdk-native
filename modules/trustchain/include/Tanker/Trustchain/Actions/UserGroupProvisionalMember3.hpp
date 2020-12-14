#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>

namespace Tanker::Trustchain::Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_PROVISIONAL_MEMBER_V3_ATTRIBUTES \
  (appPublicSignatureKey, Crypto::PublicSignatureKey),                        \
      (tankerPublicSignatureKey, Crypto::PublicSignatureKey),                 \
      (appPublicEncryptionKey, Crypto::PublicEncryptionKey),                  \
      (tankerPublicEncryptionKey, Crypto::PublicEncryptionKey),               \
      (encryptedPrivateEncryptionKey,                                         \
       Crypto::TwoTimesSealedPrivateEncryptionKey)

class UserGroupProvisionalMember3
{
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION(
      UserGroupProvisionalMember3,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_PROVISIONAL_MEMBER_V3_ATTRIBUTES)

  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupProvisionalMember3&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupProvisionalMember3)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupProvisionalMember3)
}
