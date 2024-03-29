#include <Tanker/Trustchain/Actions/UserGroupProvisionalMember3.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker::Trustchain::Actions
{
TANKER_TRUSTCHAIN_DATA_DEFINE_SERIALIZATION(UserGroupProvisionalMember3,
                                            TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_PROVISIONAL_MEMBER_V3_ATTRIBUTES)
TANKER_TRUSTCHAIN_DATA_DEFINE_TO_JSON(UserGroupProvisionalMember3,
                                      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_PROVISIONAL_MEMBER_V3_ATTRIBUTES)
}
