#pragma once

#include <Tanker/Trustchain/GroupAction.hpp>

#include <optional>

namespace Tanker
{
class BaseGroup;
namespace Users
{
class Device;
}
}

namespace Tanker::Verif
{
Trustchain::GroupAction verifyUserGroupCreation(
    Trustchain::GroupAction const& serverEntry,
    Users::Device const& author,
    std::optional<BaseGroup> const& group);
}
