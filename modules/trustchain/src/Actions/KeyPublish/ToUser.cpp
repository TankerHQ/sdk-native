#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    KeyPublishToUser, TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    KeyPublishToUser, TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_ATTRIBUTES)
}
}
}
