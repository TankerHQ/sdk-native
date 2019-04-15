#include <Tanker/Verif/TrustchainCreation.hpp>

#include <Tanker/Error.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

using Tanker::Trustchain::Actions::Nature;

namespace Tanker
{
namespace Verif
{
void verifyTrustchainCreation(Tanker::UnverifiedEntry const& rootEntry,
                              TrustchainId const& currentTrustchainId)
{
  assert(rootEntry.nature == Nature::TrustchainCreation);

  ensures(rootEntry.hash.base() == currentTrustchainId.base(),
          Error::VerificationCode::InvalidHash,
          "root block hash must be the trustchain id");
  ensures(rootEntry.author.is_null(),
          Error::VerificationCode::InvalidAuthor,
          "author must be zero-filled");
  ensures(rootEntry.signature.is_null(),
          Error::VerificationCode::InvalidSignature,
          "signature must be zero-filled");
}
}
}
