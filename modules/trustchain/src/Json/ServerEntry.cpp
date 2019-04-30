#include <Tanker/Trustchain/ServerEntry.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
void to_json(nlohmann::json& j, ServerEntry const& se)
{
  j["trustchainId"] = se.trustchainId();
  j["index"] = se.index();
  j["parentHash"] = se.parentHash();
  j["action"] = se.action();
  j["hash"] = se.hash();
  j["signature"] = se.signature();
}
}
}
