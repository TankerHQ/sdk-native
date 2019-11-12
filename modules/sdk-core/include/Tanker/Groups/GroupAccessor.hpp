#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

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

  GroupAccessor(TrustchainPuller* trustchainPuller,
                GroupStore const* groupstore);

  GroupAccessor() = delete;
  GroupAccessor(GroupAccessor const&) = delete;
  GroupAccessor(GroupAccessor&&) = delete;
  GroupAccessor& operator=(GroupAccessor const&) = delete;
  GroupAccessor& operator=(GroupAccessor&&) = delete;

  tc::cotask<PullResult> pull(gsl::span<Trustchain::GroupId const> groupIds);
  tc::cotask<nonstd::optional<InternalGroup>> getFullGroup(
      Crypto::PublicEncryptionKey const& groupKeys);

private:
  tc::cotask<void> fetch(gsl::span<Trustchain::GroupId const> groupIds);

private:
  TrustchainPuller* _trustchainPuller;
  GroupStore const* _groupStore;
};
}
