#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
struct Device;
struct ExternalGroup;

namespace Verif
{
Entry verifyUserGroupAddition(Trustchain::ServerEntry const& serverEntry,
                              Device const& author,
                              ExternalGroup const& group);
}
}
