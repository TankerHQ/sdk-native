#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <optional.hpp>

namespace Tanker
{
struct Device;

namespace Verif
{
Entry verifyUserGroupCreation(Trustchain::ServerEntry const& serverEntry,
                              Device const& author,
                              nonstd::optional<ExternalGroup> const& group);
}
}
