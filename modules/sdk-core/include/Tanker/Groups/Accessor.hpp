#pragma once

#include <Tanker/Groups/IAccessor.hpp>

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker::Users
{
class ILocalUserAccessor;
class IUserAccessor;
}

namespace Tanker::Groups
{
class Store;
class Accessor : public Groups::IAccessor
{
public:
  Accessor(Groups::IRequester* requester,
           Users::IUserAccessor* userAccessor,
           Store* groupstore,
           Users::ILocalUserAccessor* localUserAccessor,
           ProvisionalUsers::IAccessor* provisionalUserAccessor);

  Accessor() = delete;
  Accessor(Accessor const&) = delete;
  Accessor(Accessor&&) = delete;
  Accessor& operator=(Accessor const&) = delete;
  Accessor& operator=(Accessor&&) = delete;

  tc::cotask<InternalGroup> getInternalGroup(
      Trustchain::GroupId const& groupId) override;
  tc::cotask<GroupAndMembers<InternalGroup>> getInternalGroupAndMembers(
      Trustchain::GroupId const& groupId) override;
  tc::cotask<PublicEncryptionKeyPullResult> getPublicEncryptionKeys(
      std::vector<Trustchain::GroupId> const& groupIds) override;
  // This function can only return keys for groups you are a member of
  tc::cotask<std::optional<Crypto::EncryptionKeyPair>> getEncryptionKeyPair(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) override;

private:
  Groups::IRequester* _requester;
  Users::IUserAccessor* _userAccessor;
  Store* _groupStore;
  Users::ILocalUserAccessor* _localUserAccessor;
  ProvisionalUsers::IAccessor* _provisionalUserAccessor;

  tc::cotask<void> fetch(gsl::span<Trustchain::GroupId const> groupIds);
  tc::cotask<Accessor::GroupAndMembersPullResult> getGroups(
      std::vector<Trustchain::GroupId> const& groupIds,
      IRequester::IsLight isLight,
      bool fillMembers = true);
  static GroupAndMembers<Group> getGroupMembers(
      Group group, std::vector<Trustchain::GroupAction> const& entries);
};
}
