#include <Tanker/Trustchain/Actions/UserGroupMember2.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    UserGroupMember2, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_MEMBER_V2_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    UserGroupMember2, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_MEMBER_V2_ATTRIBUTES)
}
}
}
