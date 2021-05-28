#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Actions/UserGroupMember2.hpp>
#include <Tanker/Trustchain/Actions/UserGroupProvisionalMember3.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

namespace Tanker::Trustchain::Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_UPDATE_V1_ATTRIBUTES     \
  (groupId, GroupId), (previousGroupBlockHash, Crypto::Hash),         \
  (previousKeyRotationBlockHash, Crypto::Hash),                       \
      (publicSignatureKey, Crypto::PublicSignatureKey),               \
      (publicEncryptionKey, Crypto::PublicEncryptionKey),             \
      (sealedPrivateSignatureKey, Crypto::SealedPrivateSignatureKey), \
      (sealedPreviousPrivateEncryptionKey,                            \
       Crypto::SealedPrivateEncryptionKey),                           \
      (members, Members), (provisionalMembers, ProvisionalMembers),   \
      (selfSignatureWithCurrentKey, Crypto::Signature),               \
      (selfSignatureWithPreviousKey, Crypto::Signature)

class UserGroupUpdate1
{
public:
  using Members = std::vector<UserGroupMember2>;
  using ProvisionalMembers = std::vector<UserGroupProvisionalMember3>;

  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      UserGroupUpdate1,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_UPDATE_V1_ATTRIBUTES)

public:
  UserGroupUpdate1(
      TrustchainId const& trustchainId,
      GroupId const& groupId,
      Crypto::Hash const& previousGroupBlockHash,
      Crypto::Hash const& previousKeyRotationBlockHash,
      Crypto::PublicSignatureKey const& publicSignatureKey,
      Crypto::PublicEncryptionKey const& publicEncryptionKey,
      Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
      Crypto::SealedPrivateEncryptionKey const&
          sealedPreviousPrivateEncryptionKey,
      Members const& members,
      ProvisionalMembers const& provisionalMembers,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
      Crypto::PrivateSignatureKey const& groupPreviousPrivateSignatureKey,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupUpdate1&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupUpdate1)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupUpdate1)
}
