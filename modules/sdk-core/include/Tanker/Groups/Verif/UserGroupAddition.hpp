#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <optional>

namespace Tanker
{
struct Device;
struct ExternalGroup;

namespace Verif
{
Entry verifyUserGroupAddition(Trustchain::ServerEntry const& serverEntry,
                              Device const& author,
                              std::optional<ExternalGroup> const& group);
}
}
