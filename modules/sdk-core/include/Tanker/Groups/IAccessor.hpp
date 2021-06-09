#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
namespace Groups
{
class IAccessor
{
public:
  using PullResult = BasicPullResult<ExternalGroup, Trustchain::GroupId>;
  using GroupPullResult = BasicPullResult<Group, Trustchain::GroupId>;
  using GroupAndMembersPullResult =
      BasicPullResult<GroupAndMembers<Group>, Trustchain::GroupId>;
  using PublicEncryptionKeyPullResult =
      BasicPullResult<Crypto::PublicEncryptionKey, Trustchain::GroupId>;
  using EncryptionKeyPairPullResult =
      BasicPullResult<Crypto::EncryptionKeyPair, Trustchain::GroupId>;

  virtual tc::cotask<InternalGroup> getInternalGroup(
      Trustchain::GroupId const& groupId) = 0;
  virtual tc::cotask<GroupAndMembers<InternalGroup>> getInternalGroupAndMembers(
      Trustchain::GroupId const& groupId) = 0;
  virtual tc::cotask<PublicEncryptionKeyPullResult> getPublicEncryptionKeys(
      std::vector<Trustchain::GroupId> const& groupIds) = 0;
  virtual tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
  getEncryptionKeyPair(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) = 0;
};
}
}
