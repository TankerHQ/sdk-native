#include <Tanker/Groups/Requester.hpp>

#include <Tanker/Client.hpp>

#include <nlohmann/json.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Groups
{
namespace
{
tc::cotask<std::vector<Trustchain::GroupAction>> doBlockRequest(
    Client* client, nlohmann::json const& req)
{
  auto const response = TC_AWAIT(client->emit("get groups blocks", req));
  auto const blocks = response.get<std::vector<std::string>>();

  std::vector<Trustchain::GroupAction> entries;
  entries.reserve(blocks.size());
  std::transform(std::begin(blocks),
                 std::end(blocks),
                 std::back_inserter(entries),
                 [](auto const& block) {
                   return Trustchain::deserializeGroupAction(
                       mgs::base64::decode(block));
                 });

  TC_RETURN(entries);
}
}

Requester::Requester(Client* client) : _client(client)
{
}

tc::cotask<std::vector<Trustchain::GroupAction>> Requester::getGroupBlocks(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  if (groupIds.empty())
    TC_RETURN(std::vector<Trustchain::GroupAction>{});

  TC_RETURN(TC_AWAIT(doBlockRequest(_client,
                                    nlohmann::json{
                                        {"groups_ids", groupIds},
                                    })));
}

tc::cotask<std::vector<Trustchain::GroupAction>> Requester::getGroupBlocks(
    Crypto::PublicEncryptionKey const& groupEncryptionKey)
{
  TC_RETURN(
      TC_AWAIT(doBlockRequest(_client,
                              nlohmann::json{
                                  {"group_public_key", groupEncryptionKey},
                              })));
}
}
}
