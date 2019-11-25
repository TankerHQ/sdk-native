#pragma once

#include <Tanker/Groups/IAccessor.hpp>

#include <Tanker/ContactStore.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
class ITrustchainPuller;
class GroupStore;

class GroupAccessor : public Groups::IAccessor
{
public:
  GroupAccessor(Trustchain::UserId const& myUserId,
                Groups::IRequester* requester,
                ITrustchainPuller* trustchainPuller,
                ContactStore const* contactStore,
                GroupStore* groupstore,
                UserKeyStore const* userKeyStore,
                ProvisionalUserKeysStore const* provisionalUserKeysStore);

  GroupAccessor() = delete;
  GroupAccessor(GroupAccessor const&) = delete;
  GroupAccessor(GroupAccessor&&) = delete;
  GroupAccessor& operator=(GroupAccessor const&) = delete;
  GroupAccessor& operator=(GroupAccessor&&) = delete;

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
  ContactStore const* _contactStore;
  GroupStore* _groupStore;
  UserKeyStore const* _userKeyStore;
  ProvisionalUserKeysStore const* _provisionalUserKeysStore;

  tc::cotask<void> fetch(gsl::span<Trustchain::GroupId const> groupIds);
  tc::cotask<GroupAccessor::GroupPullResult> getGroups(
      std::vector<Trustchain::GroupId> const& groupIds);
};
}
