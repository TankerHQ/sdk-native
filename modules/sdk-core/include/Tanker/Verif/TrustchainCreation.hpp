#pragma once

#include <Tanker/Types/TrustchainId.hpp>

namespace Tanker
{
struct UnverifiedEntry;

namespace Verif
{
void verifyTrustchainCreation(UnverifiedEntry const&, TrustchainId const&);
}
}
