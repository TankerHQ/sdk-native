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
class LocalUser;
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
           Users::LocalUser const* localUser,
           ProvisionalUsers::IAccessor* provisionalUserAccessor);

  Accessor() = delete;
  Accessor(Accessor const&) = delete;
  Accessor(Accessor&&) = delete;
  Accessor& operator=(Accessor const&) = delete;
  Accessor& operator=(Accessor&&) = delete;

  tc::cotask<InternalGroupPullResult> getInternalGroups(
      std::vector<Trustchain::GroupId> const& groupIds) override;
  tc::cotask<PublicEncryptionKeyPullResult> getPublicEncryptionKeys(
      std::vector<Trustchain::GroupId> const& groupIds) override;
  // This function can only return keys for groups you are a member of
  tc::cotask<std::optional<Crypto::EncryptionKeyPair>> getEncryptionKeyPair(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) override;

private:
  Groups::IRequester* _requester;
  Users::IUserAccessor* _userAccessor;
  Store* _groupStore;
  Users::LocalUser const* _localUser;
  ProvisionalUsers::IAccessor* _provisionalUserAccessor;

  tc::cotask<void> fetch(gsl::span<Trustchain::GroupId const> groupIds);
  tc::cotask<Accessor::GroupPullResult> getGroups(
      std::vector<Trustchain::GroupId> const& groupIds);
};
}
