#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Actions/UserGroupMember2.hpp>
#include <Tanker/Trustchain/Actions/UserGroupProvisionalMember3.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <utility>
#include <vector>

namespace Tanker::Trustchain::Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V3_ATTRIBUTES                                     \
  (publicSignatureKey, Crypto::PublicSignatureKey), (publicEncryptionKey, Crypto::PublicEncryptionKey), \
      (sealedPrivateSignatureKey, Crypto::SealedPrivateSignatureKey), (members, Members),               \
      (provisionalMembers, ProvisionalMembers), (selfSignature, Crypto::Signature)

class UserGroupCreation3
{
public:
  using Members = std::vector<UserGroupMember2>;
  using ProvisionalMembers = std::vector<UserGroupProvisionalMember3>;

  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(UserGroupCreation3,
                                         TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V3_ATTRIBUTES)

public:
  UserGroupCreation3(TrustchainId const& trustchainId,
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
  friend void from_serialized(Serialization::SerializedSource&, UserGroupCreation3&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupCreation3)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupCreation3)
}
