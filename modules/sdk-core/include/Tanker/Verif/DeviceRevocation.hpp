#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
struct Device;
struct User;

namespace Verif
{
void verifyDeviceRevocation(Trustchain::ServerEntry const& serverEntry,
                            Device const& author,
                            Device const& target,
                            User const& user);
}
}
