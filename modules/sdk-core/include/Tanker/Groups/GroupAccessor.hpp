#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/ContactStore.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional.hpp>

namespace Tanker
{
class TrustchainPuller;
class GroupStore;

class GroupAccessor
{

public:
  using PullResult = BasicPullResult<ExternalGroup>;
  using GroupPullResult = BasicPullResult<Group, Trustchain::GroupId>;
  using InternalGroupPullResult =
      BasicPullResult<InternalGroup, Trustchain::GroupId>;
  using PublicEncryptionKeyPullResult =
      BasicPullResult<Crypto::PublicEncryptionKey, Trustchain::GroupId>;
  using EncryptionKeyPairPullResult =
      BasicPullResult<Crypto::EncryptionKeyPair, Trustchain::GroupId>;

  GroupAccessor(Trustchain::UserId const& myUserId,
                Client* client,
                TrustchainPuller* trustchainPuller,
                ContactStore const* contactStore,
                GroupStore* groupstore,
                UserKeyStore const* userKeyStore,
                ProvisionalUserKeysStore const* provisionalUserKeysStore);

  GroupAccessor() = delete;
  GroupAccessor(GroupAccessor const&) = delete;
  GroupAccessor(GroupAccessor&&) = delete;
  GroupAccessor& operator=(GroupAccessor const&) = delete;
  GroupAccessor& operator=(GroupAccessor&&) = delete;

  tc::cotask<PullResult> pull(gsl::span<Trustchain::GroupId const> groupIds);
  tc::cotask<nonstd::optional<InternalGroup>> getInternalGroup(
      Crypto::PublicEncryptionKey const& groupKeys);

  tc::cotask<GroupAccessor::InternalGroupPullResult> getInternalGroups(
      std::vector<Trustchain::GroupId> const& groupIds);
  tc::cotask<PublicEncryptionKeyPullResult> getPublicEncryptionKeys(
      std::vector<Trustchain::GroupId> const& groupIds);
  // This function can only return keys for groups you are a member of
  tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>> getEncryptionKeyPair(
      Crypto::PublicEncryptionKey const& publicEncryptionKey);

private:
  Trustchain::UserId _myUserId;
  Client* _client;
  TrustchainPuller* _trustchainPuller;
  ContactStore const* _contactStore;
  GroupStore* _groupStore;
  UserKeyStore const* _userKeyStore;
  ProvisionalUserKeysStore const* _provisionalUserKeysStore;

  tc::cotask<void> fetch(gsl::span<Trustchain::GroupId const> groupIds);
  tc::cotask<GroupAccessor::GroupPullResult> getGroups(
      std::vector<Trustchain::GroupId> const& groupIds);
};
}
