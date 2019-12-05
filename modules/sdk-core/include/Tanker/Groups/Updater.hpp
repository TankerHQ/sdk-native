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
class UserKeyStore;
}

namespace Tanker
{
namespace GroupUpdater
{
tc::cotask<Group> applyUserGroupCreation(
    Trustchain::UserId const& myUserId,
    Users::UserKeyStore const& userKeyStore,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    Entry const& entry);

tc::cotask<Group> applyUserGroupAddition(
    Trustchain::UserId const& myUserId,
    Users::UserKeyStore const& userKeyStore,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> previousGroup,
    Entry const& entry);

tc::cotask<std::optional<Group>> processGroupEntries(
    Trustchain::UserId const& myUserId,
    ITrustchainPuller& trustchainPuller,
    Users::ContactStore const& contactStore,
    Users::UserKeyStore const& userKeyStore,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> const& previousGroup,
    std::vector<Trustchain::ServerEntry> const& entries);
}
}
