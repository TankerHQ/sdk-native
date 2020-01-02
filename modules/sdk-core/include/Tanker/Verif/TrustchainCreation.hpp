#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

namespace Tanker
{
namespace Verif
{
Entry verifyTrustchainCreation(Trustchain::ServerEntry const&,
                               Trustchain::TrustchainId const&);
}
}
