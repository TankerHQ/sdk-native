#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker::Users
{
class Device;
}

namespace Tanker::Verif
{
Entry verifyProvisionalIdentityClaim(Trustchain::ServerEntry const& serverEntry,
                                     Users::Device const& author);
}
