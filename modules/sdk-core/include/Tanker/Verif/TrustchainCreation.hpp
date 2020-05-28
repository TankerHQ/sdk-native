#pragma once

#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

namespace Tanker
{
namespace Verif
{
Trustchain::Actions::TrustchainCreation verifyTrustchainCreation(
    Trustchain::Actions::TrustchainCreation const&,
    Trustchain::TrustchainId const&);
}
}
