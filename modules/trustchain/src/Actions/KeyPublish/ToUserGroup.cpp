#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    KeyPublishToUserGroup,
    TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_GROUP_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    KeyPublishToUserGroup,
    TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_GROUP_ATTRIBUTES)
}
}
}
