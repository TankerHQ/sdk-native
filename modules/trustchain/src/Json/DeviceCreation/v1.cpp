#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, DeviceCreation1 const& dc)
{
  j["ephemeralPublicSignatureKey"] = dc.ephemeralPublicSignatureKey();
  j["userId"] = dc.userId();
  j["delegationSignature"] = dc.delegationSignature();
  j["publicSignatureKey"] = dc.publicSignatureKey();
  j["publicEncryptionKey"] = dc.publicEncryptionKey();
}
}
}
}
