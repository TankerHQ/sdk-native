#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace GroupUpdater
{
tc::cotask<void> applyEntry(Trustchain::UserId const& myUserId,
                            GroupStore& groupStore,
                            UserKeyStore const& userKeyStore,
                            Entry const& entry);
}
}
