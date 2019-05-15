#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>
#include <Tanker/Trustchain/UserId.hpp>
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

tc::cotask<void> applyGroupPrivateKey(
    GroupStore& groupStore,
    ExternalGroup const& group,
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey);
}
}
