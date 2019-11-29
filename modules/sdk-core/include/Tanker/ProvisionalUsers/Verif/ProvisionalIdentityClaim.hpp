#pragma once

#include <Tanker/Device.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
struct Device;

namespace Verif
{
Entry verifyProvisionalIdentityClaim(Trustchain::ServerEntry const& serverEntry,
                                     Device const& author);
}
}
