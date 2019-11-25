#include <Tanker/ProvisionalUsers/Requests.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace ProvisionalUsers
{
namespace Requests
{
tc::cotask<std::vector<Trustchain::ServerEntry>> getClaimBlocks(Client* client)
{
  auto const response = TC_AWAIT(client->emit("get my claim blocks", {}));
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
}
}
