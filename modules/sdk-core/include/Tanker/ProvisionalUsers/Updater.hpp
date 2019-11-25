#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace ProvisionalUsers
{
namespace Updater
{
tc::cotask<void> applyEntry(UserKeyStore& userKeyStore,
                            ProvisionalUserKeysStore& provisionalUserKeysStore,
                            Entry const& entry);
}
}
}
