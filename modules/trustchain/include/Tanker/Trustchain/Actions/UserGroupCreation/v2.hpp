#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupMember2.hpp>
#include <Tanker/Trustchain/Actions/UserGroupProvisionalMember2.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V2_ATTRIBUTES   \
  (publicSignatureKey, Crypto::PublicSignatureKey),                   \
      (publicEncryptionKey, Crypto::PublicEncryptionKey),             \
      (sealedPrivateSignatureKey, Crypto::SealedPrivateSignatureKey), \
      (userGroupMembers, UserGroupMembers),                           \
      (userGroupProvisionalMembers, UserGroupProvisionalMembers),     \
      (selfSignature, Crypto::Signature)

class UserGroupCreation2
{
public:
  using UserGroupMembers = std::vector<UserGroupMember2>;
  using UserGroupProvisionalMembers = std::vector<UserGroupProvisionalMember2>;

  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION(
      UserGroupCreation2,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V2_ATTRIBUTES)

public:
  constexpr Nature nature() const;

  UserGroupCreation2(Crypto::PublicSignatureKey const&,
                     Crypto::PublicEncryptionKey const&,
                     Crypto::SealedPrivateSignatureKey const&,
                     UserGroupMembers const&,
                     UserGroupProvisionalMembers const&);

  std::vector<std::uint8_t> signatureData() const;

  Crypto::Signature const& selfSign(Crypto::PrivateSignatureKey const&);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupCreation2&);
};

constexpr Nature UserGroupCreation2::nature() const
{
  return Nature::UserGroupCreation2;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupCreation2)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupCreation2)
}
}
}
