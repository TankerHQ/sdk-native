#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
struct Device;

namespace Verif
{
void verifyUserGroupCreation(Trustchain::ServerEntry const& serverEntry,
                             Device const& author);
}
}
