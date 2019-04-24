#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, UserGroupAddition const& uga)
{
  j["groupId"] = uga.groupId();
  j["previousGroupBlockHash"] = uga.previousGroupBlockHash();
  j["sealedPrivateEncryptionKeysForUsers"] =
      uga.sealedPrivateEncryptionKeysForUsers();
  j["selfSignature"] = uga.selfSignature();
}
}
}
}
