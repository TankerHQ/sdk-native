#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <optional>

namespace Tanker::Users
{
class Device;
}

namespace Tanker::Verif
{
Entry verifyUserGroupCreation(Trustchain::ServerEntry const& serverEntry,
                              Users::Device const& author,
                              std::optional<ExternalGroup> const& group);
}
