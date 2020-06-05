#pragma once

#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

namespace Tanker::Users
{
class Device;
}

namespace Tanker::Verif
{
Trustchain::Actions::ProvisionalIdentityClaim verifyProvisionalIdentityClaim(
    Trustchain::Actions::ProvisionalIdentityClaim const& action,
    Users::Device const& author);
}
