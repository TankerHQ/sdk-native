#include <Tanker/Groups/Requests.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <mockaron/mockaron.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Groups
{
namespace Requests
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

tc::cotask<std::vector<Trustchain::ServerEntry>> getGroupBlocks(
    Client* client, std::vector<Trustchain::GroupId> const& groupIds)
{
  MOCKARON_FUNCTION_HOOK_CUSTOM(
      tc::cotask<std::vector<Trustchain::ServerEntry>>(
          Client*, std::vector<Trustchain::GroupId> const&),
      std::vector<Trustchain::ServerEntry>,
      getGroupBlocks,
      TC_RETURN,
      client,
      groupIds);

  if (groupIds.empty())
    TC_RETURN(std::vector<Trustchain::ServerEntry>{});

  TC_RETURN(TC_AWAIT(doBlockRequest(client,
                                    nlohmann::json{
                                        {"groups_ids", groupIds},
                                    })));
}

tc::cotask<std::vector<Trustchain::ServerEntry>> getGroupBlocks(
    Client* client, Crypto::PublicEncryptionKey const& groupEncryptionKey)
{
  MOCKARON_FUNCTION_HOOK_CUSTOM(
      tc::cotask<std::vector<Trustchain::ServerEntry>>(
          Client*, Crypto::PublicEncryptionKey const&),
      std::vector<Trustchain::ServerEntry>,
      getGroupBlocks,
      TC_RETURN,
      client,
      groupEncryptionKey);

  TC_RETURN(
      TC_AWAIT(doBlockRequest(client,
                              nlohmann::json{
                                  {"group_public_key", groupEncryptionKey},
                              })));
}
}
}
}
