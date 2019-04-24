#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, ProvisionalIdentityClaim const& pic)
{
  j["userId"] = pic.userId();
  j["appSignaturePublicKey"] = pic.appSignaturePublicKey();
  j["tankerSignaturePublicKey"] = pic.tankerSignaturePublicKey();
  j["authorSignatureByAppKey"] = pic.authorSignatureByAppKey();
  j["authorSignatureByTankerKey"] = pic.authorSignatureByTankerKey();
  j["userPublicEncryptionKey"] = pic.userPublicEncryptionKey();
  j["sealedPrivateEncryptionKeys"] = pic.sealedPrivateEncryptionKeys();
}
}
}
}
