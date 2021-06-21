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

tc::cotask<std::optional<Group>> processGroupEntries(
    Users::ILocalUserAccessor& localUserAccessor,
    Users::IUserAccessor& userAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> const& previousGroup,
    std::vector<Trustchain::GroupAction> const& entries);
}
}
