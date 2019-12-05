#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <optional>

namespace Tanker::Users
{
struct Device;
}

namespace Tanker
{
struct ExternalGroup;

namespace Verif
{
Entry verifyUserGroupAddition(Trustchain::ServerEntry const& serverEntry,
                              Users::Device const& author,
                              std::optional<ExternalGroup> const& group);
}
}
