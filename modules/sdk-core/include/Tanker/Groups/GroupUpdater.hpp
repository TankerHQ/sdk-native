#pragma once

#include <Tanker/ContactStore.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/ITrustchainPuller.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace GroupUpdater
{
tc::cotask<Group> applyUserGroupCreation(
    Trustchain::UserId const& myUserId,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    Entry const& entry);

tc::cotask<Group> applyUserGroupAddition(
    Trustchain::UserId const& myUserId,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    std::optional<Group> previousGroup,
    Entry const& entry);

tc::cotask<std::optional<Group>> processGroupEntries(
    Trustchain::UserId const& myUserId,
    ITrustchainPuller& trustchainPuller,
    ContactStore const& contactStore,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    std::optional<Group> const& previousGroup,
    std::vector<Trustchain::ServerEntry> const& entries);
}
}
