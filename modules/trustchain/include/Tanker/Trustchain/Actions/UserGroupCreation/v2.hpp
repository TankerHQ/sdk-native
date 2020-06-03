#pragma once

#include <Tanker/Crypto/Hash.hpp>
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
#include <Tanker/Trustchain/TrustchainId.hpp>
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
      (members, Members), (provisionalMembers, ProvisionalMembers),   \
      (selfSignature, Crypto::Signature)

class UserGroupCreation2
{
public:
  using Members = std::vector<UserGroupMember2>;
  using ProvisionalMembers = std::vector<UserGroupProvisionalMember2>;

  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      UserGroupCreation2,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V2_ATTRIBUTES)

public:
  UserGroupCreation2(
      TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& publicSignatureKey,
      Crypto::PublicEncryptionKey const& publicEncryptionKey,
      Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
      Members const& members,
      ProvisionalMembers const& provisionalMembers,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupCreation2&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupCreation2)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupCreation2)
}
}
}
