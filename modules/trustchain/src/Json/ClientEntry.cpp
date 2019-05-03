#include <Tanker/Trustchain/ClientEntry.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
void to_json(nlohmann::json& j, ClientEntry const& ce)
{
  j["trustchainId"] = ce.trustchainId();
  j["author"] = ce.author();
  j["nature"] = ce.nature();
  j["serializedPayload"] =
      cppcodec::base64_rfc4648::encode(ce.serializedPayload());
  j["signature"] = ce.signature();
  j["hash"] = ce.hash();
}
}
}
