#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/ProvisionalUserId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tuple>

namespace Tanker::Trustchain::Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_REMOVAL_ATTRIBUTES     \
  (groupId, GroupId), (membersToRemove, std::vector<UserId>),       \
      (provisionalMembersToRemove, std::vector<ProvisionalUserId>), \
      (selfSignatureWithCurrentKey, Crypto::Signature)

class UserGroupRemoval
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      UserGroupRemoval, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_REMOVAL_ATTRIBUTES)

public:
  UserGroupRemoval(
      TrustchainId const& trustchainId,
      GroupId const& groupId,
      std::vector<UserId> membersToRemove,
      std::vector<ProvisionalUserId> provisionalMembersToRemove,
      DeviceId const& author,
      Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData(DeviceId const& authorId) const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupRemoval&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupRemoval)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupRemoval)
}
