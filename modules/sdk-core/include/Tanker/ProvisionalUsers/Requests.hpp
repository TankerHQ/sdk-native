#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker
{
namespace ProvisionalUsers
{
namespace Requests
{
tc::cotask<std::vector<Trustchain::ServerEntry>> getClaimBlocks(Client* client);
}
}
}
