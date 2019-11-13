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

  GroupAccessor(Trustchain::UserId const& myUserId,
                Client* client,
                TrustchainPuller* trustchainPuller,
                ContactStore const* contactStore,
                GroupStore const* groupstore,
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

private:
  tc::cotask<void> fetch(gsl::span<Trustchain::GroupId const> groupIds);

private:
  Trustchain::UserId _myUserId;
  Client* _client;
  TrustchainPuller* _trustchainPuller;
  ContactStore const* _contactStore;
  GroupStore const* _groupStore;
  UserKeyStore const* _userKeyStore;
  ProvisionalUserKeysStore const* _provisionalUserKeysStore;
};
}
