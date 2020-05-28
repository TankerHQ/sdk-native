#include <Tanker/Verif/TrustchainCreation.hpp>

#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Verif
{
TrustchainCreation verifyTrustchainCreation(
    TrustchainCreation const& rootEntry,
    TrustchainId const& currentTrustchainId)
{
  ensures(rootEntry.hash().base() == currentTrustchainId.base(),
          Errc::InvalidHash,
          "root block hash must be the trustchain id");
  return rootEntry;
}
}
}
