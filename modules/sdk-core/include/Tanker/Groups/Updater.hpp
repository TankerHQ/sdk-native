#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/Trustchain/GroupAction.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Users
{
class IUserAccessor;
class ILocalUserAccessor;
}

namespace Tanker
{
namespace GroupUpdater
{
struct ProcessGroupResult
{
  std::optional<Group> group;
  // We can be added to and removed from a group multiple times,
  // this holds the history of the group encryption keys shared with us
  // NOTE: Keys are not currently guaranteed to be in order!
  std::vector<Crypto::EncryptionKeyPair> groupKeys;
};

tc::cotask<Group> applyUserGroupCreation(
    Users::ILocalUserAccessor& localUserAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    Trustchain::GroupAction const& action);

tc::cotask<Group> applyUserGroupAddition(
    Users::ILocalUserAccessor& localUserAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> previousGroup,
    Trustchain::GroupAction const& action);

tc::cotask<Group> applyUserGroupUpdate(
    Users::ILocalUserAccessor& localUserAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> previousGroup,
    Trustchain::GroupAction const& action);

tc::cotask<ProcessGroupResult> processGroupEntries(
    Users::ILocalUserAccessor& localUserAccessor,
    Users::IUserAccessor& userAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> const& previousGroup,
    std::vector<Trustchain::GroupAction> const& entries);
}
}
