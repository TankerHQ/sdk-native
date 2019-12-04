#include <Tanker/Groups/Requester.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Groups
{
namespace
{
tc::cotask<std::vector<Trustchain::ServerEntry>> doBlockRequest(
    Client* client, nlohmann::json const& req)
{
  auto const response = TC_AWAIT(client->emit("get groups blocks", req));
  auto const sblocks = response.get<std::vector<std::string>>();
  std::vector<Trustchain::ServerEntry> ret;
  ret.reserve(sblocks.size());
  for (auto const& sblock : sblocks)
    ret.push_back(
        blockToServerEntry(Serialization::deserialize<Trustchain::Block>(
            cppcodec::base64_rfc4648::decode(sblock))));
  TC_RETURN(ret);
}
}

Requester::Requester(Client* client) : _client(client)
{
}

tc::cotask<std::vector<Trustchain::ServerEntry>> Requester::getGroupBlocks(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  if (groupIds.empty())
    TC_RETURN(std::vector<Trustchain::ServerEntry>{});

  TC_RETURN(TC_AWAIT(doBlockRequest(_client,
                                    nlohmann::json{
                                        {"groups_ids", groupIds},
                                    })));
}

tc::cotask<std::vector<Trustchain::ServerEntry>> Requester::getGroupBlocks(
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
