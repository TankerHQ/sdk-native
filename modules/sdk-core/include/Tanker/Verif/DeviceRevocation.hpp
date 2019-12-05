#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker::Users
{
struct User;
struct Device;
}

namespace Tanker
{

namespace Verif
{
void verifyDeviceRevocation(Trustchain::ServerEntry const& serverEntry,
                            Users::Device const& author,
                            Users::Device const& target,
                            Users::User const& user);
}
}
