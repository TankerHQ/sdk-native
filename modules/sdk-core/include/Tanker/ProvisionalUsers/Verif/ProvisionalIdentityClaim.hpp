#pragma once

#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

namespace Tanker::Users
{
class Device;
}

namespace Tanker::Verif
{
Trustchain::Actions::ProvisionalIdentityClaim verifyProvisionalIdentityClaim(
    Trustchain::Actions::ProvisionalIdentityClaim const& serverEntry,
    Users::Device const& author);
}
