#pragma once

#include <Tanker/Device.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/User.hpp>

namespace Tanker
{
struct Device;

namespace Verif
{
void verifyProvisionalIdentityClaim(Trustchain::ServerEntry const& serverEntry,
                                    User const& authorUser,
                                    Device const& author);
}
}
