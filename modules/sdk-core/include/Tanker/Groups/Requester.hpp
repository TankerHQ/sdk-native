#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker
{
class HttpClient;
namespace Groups
{

class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(HttpClient* client);

  tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      gsl::span<Trustchain::GroupId const> groupIds) override;

  tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      Crypto::PublicEncryptionKey const& groupEncryptionKey) override;

private:
  tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocksImpl(
      nlohmann::json const& query);

  HttpClient* _httpClient;
};
}
}
