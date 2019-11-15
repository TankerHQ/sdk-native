#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <optional.hpp>

namespace Tanker
{
struct Device;

namespace Verif
{
void verifyUserGroupCreation(Trustchain::ServerEntry const& serverEntry,
                             Device const& author,
                             nonstd::optional<ExternalGroup> const& group);
}
}
