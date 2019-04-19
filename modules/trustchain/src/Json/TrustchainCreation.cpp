#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, TrustchainCreation const& tc)
{
  j["publicSignatureKey"] = tc.publicSignatureKey();
}
}
}
}
