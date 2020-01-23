#include <Tanker/ProvisionalUsers/Requests.hpp>

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
  auto const ret = Trustchain::fromBlocksToServerEntries(
      response.get<std::vector<std::string>>());
  TC_RETURN(ret);
}
}
}
}
