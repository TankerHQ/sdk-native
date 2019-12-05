#pragma once

#include <Tanker/Groups/IAccessor.hpp>

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
class ITrustchainPuller;
}

namespace Tanker::Users
{
class ContactStore;
class UserKeyStore;
}

namespace Tanker::Groups
{
class Store;
class Accessor : public Groups::IAccessor
{
public:
  Accessor(Trustchain::UserId const& myUserId,
           Groups::IRequester* requester,
           ITrustchainPuller* trustchainPuller,
           Users::ContactStore const* contactStore,
           Store* groupstore,
           Users::UserKeyStore const* userKeyStore,
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
  Trustchain::UserId _myUserId;
  Groups::IRequester* _requester;
  ITrustchainPuller* _trustchainPuller;
  Users::ContactStore const* _contactStore;
  Store* _groupStore;
  Users::UserKeyStore const* _userKeyStore;
  ProvisionalUsers::IAccessor* _provisionalUserAccessor;

  tc::cotask<void> fetch(gsl::span<Trustchain::GroupId const> groupIds);
  tc::cotask<Accessor::GroupPullResult> getGroups(
      std::vector<Trustchain::GroupId> const& groupIds);
};
}
