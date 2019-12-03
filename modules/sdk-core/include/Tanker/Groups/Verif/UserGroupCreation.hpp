#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <optional>

namespace Tanker
{
struct Device;

namespace Verif
{
Entry verifyUserGroupCreation(Trustchain::ServerEntry const& serverEntry,
                              Device const& author,
                              std::optional<ExternalGroup> const& group);
}
}
