#pragma once

#include <Tanker/Trustchain/GroupAction.hpp>

#include <optional>

namespace Tanker::Users
{
class Device;
}

namespace Tanker
{
class BaseGroup;

namespace Verif
{
Trustchain::GroupAction verifyUserGroupUpdate(
    Trustchain::GroupAction const& action,
    Users::Device const& author,
    std::optional<BaseGroup> const& group);
}
}
