#pragma once

#include <Tanker/ContactStore.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace GroupUpdater
{
tc::cotask<void> applyEntry(
    Trustchain::UserId const& myUserId,
    GroupStore& groupStore,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    Entry const& entry);

tc::cotask<nonstd::optional<Group>> processGroupEntries(
    Trustchain::UserId const& myUserId,
    TrustchainPuller& trustchainPuller,
    ContactStore const& contactStore,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    nonstd::optional<Group> const& previousGroup,
    std::vector<Trustchain::ServerEntry> const& entries);
}
}
