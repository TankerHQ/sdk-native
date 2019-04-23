#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Preregistration
{
tc::cotask<void> applyEntry(UserKeyStore& userKeyStore,
                            ProvisionalUserKeysStore& provisionalUserKeysStore,
                            Entry const& entry);
}
}
