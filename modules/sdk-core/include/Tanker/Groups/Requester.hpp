#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker
{
class Client;
namespace Groups
{

class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Client* client);

  tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      std::vector<Trustchain::GroupId> const& groupIds) override;

  tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      Crypto::PublicEncryptionKey const& groupEncryptionKey) override;

private:
  Client* _client;
};
}
}
