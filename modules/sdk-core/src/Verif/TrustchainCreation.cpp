#include <Tanker/Verif/TrustchainCreation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Verif
{
void verifyTrustchainCreation(ServerEntry const& rootEntry,
                              TrustchainId const& currentTrustchainId)
{
  assert(rootEntry.action().nature() == Nature::TrustchainCreation);

  ensures(rootEntry.hash().base() == currentTrustchainId.base(),
          Error::VerificationCode::InvalidHash,
          "root block hash must be the trustchain id");
  ensures(rootEntry.author().is_null(),
          Error::VerificationCode::InvalidAuthor,
          "author must be zero-filled");
  ensures(rootEntry.signature().is_null(),
          Error::VerificationCode::InvalidSignature,
          "signature must be zero-filled");
}
}
}
