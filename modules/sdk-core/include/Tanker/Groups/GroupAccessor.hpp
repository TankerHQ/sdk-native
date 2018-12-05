#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Groups/Group.hpp>

#include <tconcurrent/coroutine.hpp>

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

  tc::cotask<PullResult> pull(gsl::span<GroupId const> groupIds);

private:
  tc::cotask<void> fetch(gsl::span<GroupId const> groupIds);

private:
  TrustchainPuller* _trustchainPuller;
  GroupStore const* _groupStore;
};
}
