#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker
{
namespace Network
{
class HttpClient;
}

namespace Groups
{
class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Network::HttpClient* client);

  tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      gsl::span<Trustchain::GroupId const> groupIds, IsLight isLight) override;

  tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      Crypto::PublicEncryptionKey const& groupEncryptionKey) override;

  tc::cotask<void> createGroup(
      Trustchain::Actions::UserGroupCreation const& groupCreation) override;

  tc::cotask<void> updateGroup(
      Trustchain::Actions::UserGroupAddition const& groupAddition) override;

  tc::cotask<void> updateGroup(
      Trustchain::Actions::UserGroupUpdate const& groupUpdate) override;

private:
  tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocksImpl(
      nlohmann::json const& query);

  Network::HttpClient* _httpClient;
};
}
}
