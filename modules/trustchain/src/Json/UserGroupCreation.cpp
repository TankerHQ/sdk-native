#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, UserGroupCreation const& ugc)
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
