#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker
{
namespace Groups
{
namespace Requests
{
tc::cotask<std::vector<Trustchain::ServerEntry>> getGroupBlocks(
    Client& client, std::vector<Trustchain::GroupId> const& groupIds);

tc::cotask<std::vector<Trustchain::ServerEntry>> getGroupBlocks(
    Client& client, Crypto::PublicEncryptionKey const& groupEncryptionKey);
}
}
}
