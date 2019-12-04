#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker
{
class Client;
namespace Groups
{

class Requester : public IRequester
{
public:
  Requester(Client* client);

  tc::cotask<std::vector<Trustchain::ServerEntry>> getGroupBlocks(
      std::vector<Trustchain::GroupId> const& groupIds) override;

  tc::cotask<std::vector<Trustchain::ServerEntry>> getGroupBlocks(
      Crypto::PublicEncryptionKey const& groupEncryptionKey) override;

private:
  Client* _client;
};
}
}
