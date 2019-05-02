#include <Tanker/Trustchain/Actions/UserGroupCreation/v1.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, UserGroupCreation1 const& ugc)
{
  j["publicSignatureKey"] = ugc.publicSignatureKey();
  j["publicEncryptionKey"] = ugc.publicEncryptionKey();
  j["sealedPrivateSignatureKey"] = ugc.sealedPrivateSignatureKey();
  j["sealedPrivateEncryptionKeysForUsers"] =
      ugc.sealedPrivateEncryptionKeysForUsers();
  j["selfSignature"] = ugc.selfSignature();
}
}
}
}
