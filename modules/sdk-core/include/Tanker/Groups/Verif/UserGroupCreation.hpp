#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

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
Entry verifyUserGroupCreation(Trustchain::ServerEntry const& serverEntry,
                              Users::Device const& author,
                              std::optional<BaseGroup> const& group);
}
