#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

namespace Tanker
{
namespace Verif
{
void verifyTrustchainCreation(Trustchain::ServerEntry const&,
                              Trustchain::TrustchainId const&);
}
}
