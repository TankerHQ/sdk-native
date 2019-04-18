#pragma once

#include <Tanker/Device.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/User.hpp>

namespace Tanker
{
struct UnverifiedEntry;
struct Device;

namespace Verif
{
void verifyProvisionalIdentityClaim(UnverifiedEntry const& entry,
                                    User const& authorUser,
                                    Device const& author);
}
}
