#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/ITrustchainPuller.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Users
{
class ContactStore;
class LocalUser;
}

namespace Tanker
{
namespace GroupUpdater
{
tc::cotask<Group> applyUserGroupCreation(
    Users::LocalUser const& localUser,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    Entry const& entry);

tc::cotask<Group> applyUserGroupAddition(
    Users::LocalUser const& localUser,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> previousGroup,
    Entry const& entry);

tc::cotask<std::optional<Group>> processGroupEntries(
    ITrustchainPuller& trustchainPuller,
    Users::LocalUser const& localUser,
    Users::ContactStore const& contactStore,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> const& previousGroup,
    std::vector<Trustchain::ServerEntry> const& entries);
}
}
