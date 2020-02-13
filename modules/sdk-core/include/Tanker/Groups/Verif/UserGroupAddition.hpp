#pragma once

#include <Tanker/Entry.hpp>

#include <optional>

namespace Tanker::Users
{
class Device;
}

namespace Tanker
{
class BaseGroup;

namespace Trustchain
{
class ServerEntry;
}

namespace Verif
{
Entry verifyUserGroupAddition(Trustchain::ServerEntry const& serverEntry,
                              Users::Device const& author,
                              std::optional<BaseGroup> const& group);
}
}
