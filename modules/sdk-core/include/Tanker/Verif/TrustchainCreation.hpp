#pragma once

#include <Tanker/Trustchain/TrustchainId.hpp>

namespace Tanker
{
struct UnverifiedEntry;

namespace Verif
{
void verifyTrustchainCreation(UnverifiedEntry const&,
                              Trustchain::TrustchainId const&);
}
}
